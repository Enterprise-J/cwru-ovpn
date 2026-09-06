#include "cwru_openvpn3_wrapper.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <new>
#include <string>
#include <thread>

#include <openssl/ssl.h>

#include "ovpncli.hpp"

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
        if (!is_callback_thread())
            callback_finished_.wait(lock, [this] { return active_callbacks_ == 0; });
        callback_ = callback_arg;
        callback_context_ = context_arg;
    }

    bool start(const std::string &config_content,
               const std::string &gui_version,
               const std::string &sso_methods,
               const std::string &allow_unused_addr_families,
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

        config_ = Config{};
        config_.content = config_content;
        config_.guiVersion = gui_version;
        config_.ssoMethods = sso_methods;
        config_.info = true;
        config_.echo = true;
        config_.dco = false;
        config_.allowUnusedAddrFamilies = allow_unused_addr_families;
        config_.serverOverride = server_override;
        config_.tunPersist = true;
        config_.protoVersionOverride = 4;
        const EvalConfig eval = eval_config(config_);
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
        clear_callback();
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
        if (worker_started)
            OpenVPNClient::stop();
    }

    void stop_and_join()
    {
        stop_requested_.store(true, std::memory_order_release);
        std::thread worker;
        bool called_from_worker = false;
        {
            std::scoped_lock lock(mutex_);
            if (!worker_.joinable())
                return;
            called_from_worker = worker_.get_id() == std::this_thread::get_id();
        }

        OpenVPNClient::stop();
        if (called_from_worker || is_callback_thread())
            return;

        {
            std::scoped_lock lock(mutex_);
            if (!worker_.joinable())
                return;
            worker = std::move(worker_);
        }
        worker.join();
    }

    bool is_callback_thread() const
    {
        return active_callback_owner_ == this;
    }

    void clear_callback()
    {
        std::unique_lock lock(mutex_);
        callback_ = nullptr;
        callback_context_ = nullptr;
        if (!is_callback_thread())
            callback_finished_.wait(lock, [this] { return active_callbacks_ == 0; });
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

    char *copy_vpn_gateway_ipv4() const
    {
        std::scoped_lock lock(mutex_);
        return dup_string(last_info_.gw4);
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

        BridgeClient *previous_callback_owner = active_callback_owner_;
        active_callback_owner_ = this;
        try
        {
            callback(context, name.c_str(), info.c_str(), is_error, is_fatal);
        }
        catch (...)
        {
            active_callback_owner_ = previous_callback_owner;
            finish_callback();
            throw;
        }
        active_callback_owner_ = previous_callback_owner;
        finish_callback();
    }

    void finish_callback()
    {
        std::scoped_lock lock(mutex_);
        --active_callbacks_;
        callback_finished_.notify_all();
    }

    mutable std::mutex mutex_;
    std::condition_variable callback_finished_;
    cwru_ovpn_event_callback_t callback_ = nullptr;
    void *callback_context_ = nullptr;
    std::size_t active_callbacks_ = 0;
    std::thread worker_;
    std::atomic<bool> worker_finished_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> terminal_event_emitted_{false};
    bool worker_started_once_ = false;
    inline static thread_local BridgeClient *active_callback_owner_ = nullptr;
    Config config_;
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
    if (!client)
        return;

    try
    {
        if (client->impl.is_callback_thread())
        {
            client->impl.clear_callback();
            client->impl.request_stop();
            std::thread reaper([client] { delete client; });
            reaper.detach();
            return;
        }
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

bool cwru_ovpn_client_start(cwru_ovpn_client_t *client,
                           const char *config_content,
                           const char *gui_version,
                           const char *sso_methods,
                           const char *allow_unused_addr_families,
                           const char *server_override,
                           char **error_message)
{
    if (error_message)
        *error_message = nullptr;

    if (!client || !config_content)
    {
        set_error_message(error_message, "OpenVPN 3 client is not initialized");
        return false;
    }

    std::string error;
    try
    {
        const bool started = client->impl.start(
            config_content,
            gui_version ? gui_version : "cwru-ovpn",
            sso_methods ? sso_methods : "webauth",
            allow_unused_addr_families ? allow_unused_addr_families : "no",
            server_override ? server_override : "",
            error);

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

char *cwru_ovpn_client_copy_vpn_gateway_ipv4(const cwru_ovpn_client_t *client)
{
    try { return client ? client->impl.copy_vpn_gateway_ipv4() : nullptr; } catch (...) { return nullptr; }
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

void cwru_ovpn_string_free(char *value)
{
    std::free(value);
}

}
