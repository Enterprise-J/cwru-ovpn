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
#import <Foundation/Foundation.h>

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
bool enumerate_profile_options(const char *content, cwru_ovpn_profile_option_callback_t callback,
                               char **error_message, Enumerate enumerate)
{
    if (error_message)
        *error_message = nullptr;
    if (!content || !callback)
    {
        set_error_message(error_message, "A profile and option callback are required");
        return false;
    }
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

NSString *string_value(const std::string &value)
{
    if (value.size() > 1024 || value.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid field in the connection snapshot");
    NSString *string = [NSString stringWithUTF8String:value.c_str()];
    if (!string)
        throw std::runtime_error("Invalid UTF-8 in the connection snapshot");
    return string;
}

std::string encode_connection(const ConnectionInfo &info)
{
    @autoreleasepool
    {
        const auto &dns = info.dnsOptions;
        if (!info.defined || dns.servers.size() > 16 || dns.search_domains.size() > 128)
            throw std::runtime_error("Invalid connection snapshot");
        NSMutableArray *servers = [NSMutableArray array];
        NSMutableArray *search = [NSMutableArray array];
        std::size_t address_count = 0;
        std::size_t domain_count = dns.search_domains.size();
        for (const auto &[priority, server] : dns.servers)
        {
            address_count += server.addresses.size();
            domain_count += server.domains.size();
            if (address_count > 16 || domain_count > 128)
                throw std::runtime_error("Too many DNS addresses or domains to save the session");
            NSMutableArray *addresses = [NSMutableArray array];
            NSMutableArray *domains = [NSMutableArray array];
            for (const auto &address : server.addresses)
                [addresses addObject:@{@"address": string_value(address.address), @"port": @(address.port)}];
            for (const auto &domain : server.domains)
                [domains addObject:string_value(domain.domain)];
            [servers addObject:@{@"priority": @(priority), @"addresses": addresses, @"domains": domains,
                                 @"security": string_value(server.dnssec_string()),
                                 @"transport": string_value(server.transport_string()), @"sni": string_value(server.sni)}];
        }
        for (const auto &domain : dns.search_domains)
            [search addObject:string_value(domain.domain)];
        NSDictionary *snapshot = @{
            @"tunnelName": string_value(info.tunName), @"vpnIPv4": string_value(info.vpnIp4),
            @"vpnIPv6": string_value(info.vpnIp6), @"serverHost": string_value(info.serverHost),
            @"serverIP": string_value(info.serverIp), @"dns": @{@"servers": servers, @"searchDomains": search}
        };
        NSData *payload = [NSJSONSerialization dataWithJSONObject:snapshot options:0 error:nullptr];
        if (!payload || payload.length > 32 * 1024)
            throw std::runtime_error("Could not save the connection details within the size limit");
        return std::string(static_cast<const char *>(payload.bytes), payload.length);
    }
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
        return request_id && request_id == pending_protection_id_ && std::chrono::steady_clock::now() < protection_deadline_
               && !protection_decided_ && !stop_requested_.load(std::memory_order_acquire);
    }

    bool complete_transport_endpoint(uint64_t request_id, bool allowed)
    {
        std::scoped_lock lock(mutex_);
        if (!request_id || request_id != pending_protection_id_
            || std::chrono::steady_clock::now() >= protection_deadline_ || protection_decided_ || stop_requested_.load(std::memory_order_acquire))
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
        std::scoped_lock lock(mutex_);
        if (worker_.joinable() && !worker_finished_.load(std::memory_order_acquire))
        {
            error_message = "VPN session is already running";
            return false;
        }
        if (worker_started_once_)
        {
            error_message = "This OpenVPN client is single-use. Create a new client for another session";
            return false;
        }

        Config config{};
        config.content = config_content;
        config.guiVersion = gui_version;
        config.ssoMethods = sso_methods;
        config.info = true;
        config.dhcpSearchDomainsAsSplitDomains = false;
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
            protection_deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            protection_decided_ = false;
            protection_allowed_ = false;
        }
        emit("TRANSPORT_ENDPOINT", std::to_string(request_id) + " " + remote, false, false);
        std::unique_lock lock(mutex_);
        protection_finished_.wait_until(lock, protection_deadline_, [this] {
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
            const auto snapshot = encode_connection(connection_info());
            emit(event.name, snapshot, event.error, event.fatal);
            return;
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
    std::chrono::steady_clock::time_point protection_deadline_;
    bool protection_decided_ = false;
    bool protection_allowed_ = false;
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

bool cwru_ovpn_profile_enumerate_options(const char *profile_content,
                                         cwru_ovpn_profile_option_callback_t callback,
                                         void *context,
                                         char **error_message)
{
    return enumerate_profile_options(profile_content, callback, error_message, [&] {
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
    return enumerate_profile_options(connection_block_content, callback, error_message, [&] {
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
