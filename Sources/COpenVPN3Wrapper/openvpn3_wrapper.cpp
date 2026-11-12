#include "cwru_openvpn3_wrapper.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#include "ovpncli.hpp"

#define OPENVPN_LOG_CLASS openvpn::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO openvpn::ClientAPI::LogInfo
#include <openvpn/log/logthread.hpp>

#include <openvpn/client/cliconstants.hpp>
#include <openvpn/common/options.hpp>

using openvpn::ClientAPI::AppCustomControlMessageEvent;
using openvpn::ClientAPI::Config;
using openvpn::ClientAPI::ConnectionInfo;
using openvpn::ClientAPI::EvalConfig;
using openvpn::ClientAPI::Event;
using openvpn::ClientAPI::ExternalPKICertRequest;
using openvpn::ClientAPI::ExternalPKISignRequest;
using openvpn::ClientAPI::LogInfo;
using openvpn::ClientAPI::OpenVPNClient;
using openvpn::ClientAPI::Status;
using openvpn::Option;
using openvpn::OptionList;

namespace {

char *dup_string(const std::string &value)
{
    return ::strdup(value.c_str());
}

void set_error_message(char **error_message, const std::string &message)
{
    if (error_message)
        *error_message = dup_string(message);
}

void report_profile_options(const OptionList &options,
                            const bool access_server_metadata,
                            const cwru_ovpn_profile_option_callback_t callback,
                            void *context)
{
    std::vector<const char *> arguments;
    for (const Option &option : options)
    {
        arguments.clear();
        for (std::size_t index = 0; index < option.size(); ++index)
            arguments.push_back(option.ref(index).c_str());
        const cwru_ovpn_profile_option_kind_t kind =
            access_server_metadata ? CWRU_OVPN_PROFILE_OPTION_ACCESS_SERVER_METADATA
            : option.meta()        ? CWRU_OVPN_PROFILE_OPTION_BLOCK
                                   : CWRU_OVPN_PROFILE_OPTION_DIRECTIVE;
        callback(context, kind, arguments.data(), arguments.size());
    }
}

constexpr std::uint64_t connection_block_max_bytes = 4096;

template <typename Enumerate>
bool enumerate_profile_options(char **error_message, Enumerate enumerate)
{
    *error_message = nullptr;
    try
    {
        enumerate();
        return true;
    }
    catch (const std::exception &exception)
    {
        set_error_message(error_message, exception.what());
    }
    catch (...)
    {
        set_error_message(error_message, "OpenVPN 3 failed to parse the profile with an unknown C++ exception");
    }
    return false;
}

class BridgeClient final : public OpenVPNClient
{
  public:
    BridgeClient() = default;

    ~BridgeClient() override
    {
        shutdown();
    }

    void set_callback(cwru_ovpn_event_callback_t callback_arg, void *context_arg)
    {
        std::unique_lock lock(mutex_);
        callback_ = callback_arg;
        callback_context_ = context_arg;
        callback_finished_.wait(lock, [this] { return active_callbacks_ == 0; });
    }

    bool transport_endpoint_pending(uint64_t request_id) const
    {
        std::scoped_lock lock(mutex_);
        return request_id && request_id == pending_protection_id_
               && !protection_decided_ && !stop_requested_.load(std::memory_order_acquire);
    }

    bool complete_transport_endpoint(uint64_t request_id, bool allowed)
    {
        std::scoped_lock lock(mutex_);
        if (!request_id || request_id != pending_protection_id_
            || protection_decided_ || stop_requested_.load(std::memory_order_acquire))
            return false;
        protection_allowed_ = allowed;
        protection_decided_ = true;
        protection_finished_.notify_all();
        return true;
    }

    bool start(const std::string &config_content,
               const std::string &gui_version,
               const std::string &sso_methods,
               const std::string &server_override,
               std::string &error_message)
    {
        join_finished_worker();

        std::scoped_lock lock(mutex_);
        if (worker_.joinable())
        {
            error_message = "VPN session is already running";
            return false;
        }
        if (worker_started_once_)
        {
            error_message = "This OpenVPN client is single-use; create a new client for another session";
            return false;
        }

        last_info_ = ConnectionInfo{};

        Config config{};
        config.content = config_content;
        config.guiVersion = gui_version;
        config.ssoMethods = sso_methods;
        config.info = true;
        config.echo = true;
        config.dco = false;
        config.allowUnusedAddrFamilies = "yes";
        config.serverOverride = server_override;
        config.tunPersist = true;
        config.protoVersionOverride = 4;
        const EvalConfig eval = eval_config(config);
        if (eval.error)
        {
            error_message = eval.message;
            return false;
        }
        if (!eval.autologin)
        {
            error_message = "Only autologin certificate profiles are supported.";
            return false;
        }

        worker_finished_.store(false, std::memory_order_release);
        stop_requested_.store(false, std::memory_order_release);
        terminal_event_emitted_.store(false, std::memory_order_release);
        worker_ = std::thread([this] { connect_thread(); });
        worker_started_once_ = true;
        return true;
    }

    void shutdown()
    {
        request_stop();
        set_callback(nullptr, nullptr);
        stop_and_join();
    }

    void request_stop()
    {
        stop_requested_.store(true, std::memory_order_release);
        bool worker_started = false;
        {
            std::scoped_lock lock(mutex_);
            worker_started = worker_.joinable();
        }
        protection_finished_.notify_all();
        if (worker_started)
            OpenVPNClient::stop();
    }

    void stop_and_join()
    {
        stop_requested_.store(true, std::memory_order_release);
        {
            std::scoped_lock lock(mutex_);
            if (!worker_.joinable())
                return;
        }
        protection_finished_.notify_all();

        OpenVPNClient::stop();

        std::thread worker;
        {
            std::scoped_lock lock(mutex_);
            if (!worker_.joinable())
                return;
            worker = std::move(worker_);
        }
        worker.join();
    }

    char *copy_tun_name() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.tunName);
    }

    char *copy_vpn_ipv4() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.vpnIp4);
    }

    char *copy_vpn_ipv6() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.vpnIp6);
    }

    char *copy_server_host() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.serverHost);
    }

    char *copy_server_ip() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.serverIp);
    }

    void reconnect(const int seconds)
    {
        OpenVPNClient::reconnect(seconds);
    }

    bool is_running() const
    {
        std::scoped_lock lock(mutex_);
        return worker_.joinable() && !worker_finished_.load(std::memory_order_acquire);
    }

    bool pause_on_connection_timeout() override
    {
        return false;
    }

    bool socket_protect(openvpn_io::detail::socket_type, std::string remote, bool ipv6) override
    {
        if (ipv6 || stop_requested_.load(std::memory_order_acquire))
            return false;
        uint64_t request_id;
        {
            std::scoped_lock lock(mutex_);
            if (++next_protection_id_ == 0)
                ++next_protection_id_;
            request_id = pending_protection_id_ = next_protection_id_;
            protection_decided_ = false;
            protection_allowed_ = false;
        }
        emit("TRANSPORT_ENDPOINT", std::to_string(request_id) + " " + remote, false, false);
        std::unique_lock lock(mutex_);
        protection_finished_.wait_for(lock, std::chrono::seconds(10), [this] {
            return protection_decided_ || stop_requested_.load(std::memory_order_acquire);
        });
        const bool allowed = protection_decided_ && protection_allowed_
                             && !stop_requested_.load(std::memory_order_acquire);
        pending_protection_id_ = 0;
        lock.unlock();
        if (!allowed && !stop_requested_.load(std::memory_order_acquire))
            emit("TRANSPORT_PROTECTION_FAILED", remote, true, false);
        return allowed && !stop_requested_.load(std::memory_order_acquire);
    }

    void event(const Event &event) override
    {
        if (event.fatal || event.name == "DISCONNECTED")
            terminal_event_emitted_.store(true, std::memory_order_release);
        if (event.name == "CONNECTED")
        {
            std::scoped_lock lock(mutex_);
            last_info_ = connection_info();
        }

        emit(event.name, event.info, event.error, event.fatal);
    }

    void acc_event(const AppCustomControlMessageEvent &event) override
    {
        emit("APP_CONTROL_MESSAGE", event.protocol + ":" + event.payload, false, false);
    }

    void log(const LogInfo &log_info) override
    {
        emit("LOG", log_info.text, false, false);
    }

    void external_pki_cert_request(ExternalPKICertRequest &request) override
    {
        request.error = true;
        request.errorText = "External PKI profiles are not supported.";
    }

    void external_pki_sign_request(ExternalPKISignRequest &request) override
    {
        request.error = true;
        request.errorText = "External PKI signing is not supported.";
    }

  private:
    void join_finished_worker()
    {
        std::thread worker;
        {
            std::scoped_lock lock(mutex_);
            if (!worker_.joinable() || !worker_finished_.load(std::memory_order_acquire))
                return;
            worker = std::move(worker_);
        }

        worker.join();
    }

    void connect_thread()
    {
        try
        {
            const Status status = connect();
            if (status.error)
                emit("CORE_STATUS", status.message, true, true);
            else if (!stop_requested_.load(std::memory_order_acquire)
                     && !terminal_event_emitted_.load(std::memory_order_acquire))
                emit("CORE_EXIT", "OpenVPN worker exited without a terminal event", true, true);
        }
        catch (const std::exception &error)
        {
            emit("CORE_STATUS", error.what(), true, true);
        }
        catch (...)
        {
            emit("CORE_STATUS", "OpenVPN worker failed with an unknown C++ exception", true, true);
        }
        worker_finished_.store(true, std::memory_order_release);
    }

    void emit(const std::string &name,
              const std::string &info,
              const bool is_error,
              const bool is_fatal)
    {
        cwru_ovpn_event_callback_t callback = nullptr;
        void *context = nullptr;
        {
            std::scoped_lock lock(mutex_);
            callback = callback_;
            context = callback_context_;
            if (callback)
                ++active_callbacks_;
        }

        if (!callback)
            return;

        callback(context, name.c_str(), info.c_str(), is_error, is_fatal);

        std::scoped_lock lock(mutex_);
        --active_callbacks_;
        callback_finished_.notify_all();
    }

    mutable std::mutex mutex_;
    std::condition_variable callback_finished_;
    std::condition_variable protection_finished_;
    cwru_ovpn_event_callback_t callback_ = nullptr;
    void *callback_context_ = nullptr;
    std::size_t active_callbacks_ = 0;
    std::thread worker_;
    std::atomic<bool> worker_finished_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> terminal_event_emitted_{false};
    bool worker_started_once_ = false;
    uint64_t next_protection_id_ = 0;
    uint64_t pending_protection_id_ = 0;
    bool protection_decided_ = false;
    bool protection_allowed_ = false;
    ConnectionInfo last_info_;
};

}

struct cwru_ovpn_client
{
    BridgeClient impl;
};

extern "C" {

cwru_ovpn_client_t *cwru_ovpn_client_create(void)
{
    try
    {
        if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1)
            return nullptr;
        return new cwru_ovpn_client_t{};
    }
    catch (...)
    {
        return nullptr;
    }
}

void cwru_ovpn_client_destroy(cwru_ovpn_client_t *client)
{
    try
    {
        delete client;
    }
    catch (...)
    {
    }
}

void cwru_ovpn_client_set_event_callback(cwru_ovpn_client_t *client,
                                        cwru_ovpn_event_callback_t callback,
                                        void *context)
{
    try
    {
        if (client)
            client->impl.set_callback(callback, context);
    }
    catch (...)
    {
    }
}

bool cwru_ovpn_client_transport_endpoint_pending(const cwru_ovpn_client_t *client, uint64_t request_id)
{
    try
    {
        return client && client->impl.transport_endpoint_pending(request_id);
    }
    catch (...)
    {
        return false;
    }
}

bool cwru_ovpn_client_complete_transport_endpoint(cwru_ovpn_client_t *client, uint64_t request_id, bool allowed)
{
    try
    {
        return client && client->impl.complete_transport_endpoint(request_id, allowed);
    }
    catch (...)
    {
        return false;
    }
}

bool cwru_ovpn_client_start(cwru_ovpn_client_t *client,
                           const char *config_content,
                           const char *gui_version,
                           const char *sso_methods,
                           const char *server_override,
                           char **error_message)
{
    if (error_message)
        *error_message = nullptr;

    if (!client || !config_content || !gui_version || !sso_methods || !server_override)
    {
        set_error_message(error_message, "OpenVPN 3 client is not initialized");
        return false;
    }

    std::string error;
    try
    {
        const bool started = client->impl.start(config_content, gui_version, sso_methods, server_override, error);

        if (!started)
            set_error_message(error_message, error);

        return started;
    }
    catch (const std::exception &exception)
    {
        set_error_message(error_message, exception.what());
    }
    catch (...)
    {
        set_error_message(error_message, "OpenVPN 3 failed with an unknown C++ exception");
    }

    return false;
}

void cwru_ovpn_client_stop(cwru_ovpn_client_t *client)
{
    try
    {
        if (client)
            client->impl.request_stop();
    }
    catch (...)
    {
    }
}

void cwru_ovpn_client_shutdown(cwru_ovpn_client_t *client)
{
    try
    {
        if (client)
            client->impl.shutdown();
    }
    catch (...)
    {
    }
}

void cwru_ovpn_client_reconnect(cwru_ovpn_client_t *client, int seconds)
{
    try
    {
        if (client)
            client->impl.reconnect(seconds);
    }
    catch (...)
    {
    }
}

bool cwru_ovpn_client_is_running(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.is_running() : false; } catch (...) { return false; }
}

char *cwru_ovpn_client_copy_tun_name(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_tun_name() : nullptr; } catch (...) { return nullptr; }
}

char *cwru_ovpn_client_copy_vpn_ipv4(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_vpn_ipv4() : nullptr; } catch (...) { return nullptr; }
}

char *cwru_ovpn_client_copy_vpn_ipv6(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_vpn_ipv6() : nullptr; } catch (...) { return nullptr; }
}

char *cwru_ovpn_client_copy_server_host(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_server_host() : nullptr; } catch (...) { return nullptr; }
}

char *cwru_ovpn_client_copy_server_ip(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_server_ip() : nullptr; } catch (...) { return nullptr; }
}

bool cwru_ovpn_profile_enumerate_options(const char *profile_content,
                                         cwru_ovpn_profile_option_callback_t callback,
                                         void *context,
                                         char **error_message)
{
    return enumerate_profile_options(error_message, [&] {
        OptionList::Limits limits("profile is too large",
                                  openvpn::ProfileParseLimits::MAX_PROFILE_SIZE,
                                  openvpn::ProfileParseLimits::OPT_OVERHEAD,
                                  openvpn::ProfileParseLimits::TERM_OVERHEAD,
                                  openvpn::ProfileParseLimits::MAX_LINE_SIZE,
                                  openvpn::ProfileParseLimits::MAX_DIRECTIVE_SIZE);
        const std::string content(profile_content);
        OptionList options;
        options.parse_from_config(content, &limits);
        OptionList access_server_metadata;
        access_server_metadata.parse_meta_from_config(content, "OVPN_ACCESS_SERVER", &limits);
        report_profile_options(options, false, callback, context);
        report_profile_options(access_server_metadata, true, callback, context);
    });
}

bool cwru_ovpn_profile_enumerate_connection_block_options(const char *connection_block_content,
                                                          cwru_ovpn_profile_option_callback_t callback,
                                                          void *context,
                                                          char **error_message)
{
    return enumerate_profile_options(error_message, [&] {
        OptionList::Limits limits("<connection> block is too large",
                                  connection_block_max_bytes,
                                  openvpn::ProfileParseLimits::OPT_OVERHEAD,
                                  openvpn::ProfileParseLimits::TERM_OVERHEAD,
                                  openvpn::ProfileParseLimits::MAX_LINE_SIZE,
                                  openvpn::ProfileParseLimits::MAX_DIRECTIVE_SIZE);
        OptionList options;
        options.parse_from_config(connection_block_content, &limits);
        report_profile_options(options, false, callback, context);
    });
}

void cwru_ovpn_string_free(char *value)
{
    std::free(value);
}

}
