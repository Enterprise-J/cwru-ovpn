#include "cwru_openvpn3_wrapper.h"

// Keep OpenVPN 3 touchpoints concentrated here.
// Compare against the upstream ovpncli sources when updating this vendor copy.

#include <cstring>
#include <mutex>
#include <string>
#include <thread>

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

class BridgeClient final : public OpenVPNClient
{
  public:
    BridgeClient() = default;

    ~BridgeClient() override
    {
        stop_and_join();
    }

    void set_callback(cwru_ovpn_event_callback_t callback_arg, void *context_arg)
    {
        std::scoped_lock lock(mutex_);
        callback_ = callback_arg;
        callback_context_ = context_arg;
    }

    bool start(const std::string &config_content,
               const std::string &gui_version,
               const std::string &sso_methods,
               std::string &error_message)
    {
        std::scoped_lock lock(mutex_);
        if (worker_.joinable())
        {
            error_message = "VPN session is already running";
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
        // Fail closed when the tunnel lacks one IP family instead of silently
        // leaving native connectivity enabled outside the VPN.
        config_.allowUnusedAddrFamilies = "no";
        // Keep the utun device stable across reconnects and in-place mode switches.
        config_.tunPersist = true;
        // Force IPv4 transport: split-tunnel disables physical IPv6 to prevent leaks,
        // which kills any IPv6 OpenVPN session and triggers a tear-down/reconnect cycle.
        config_.protoVersionOverride = 4;
        config_.enableLegacyAlgorithms = CWRU_OVPN_ENABLE_LEGACY_ALGORITHMS == 1;
        config_.enableNonPreferredDCAlgorithms = CWRU_OVPN_ENABLE_NON_PREFERRED_DC_ALGORITHMS == 1;

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

        worker_ = std::thread([this] { connect_thread(); });
        return true;
    }

    void stop_and_join()
    {
        OpenVPNClient::stop();
        if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id())
            worker_.join();
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

    bool pause_on_connection_timeout() override
    {
        return false;
    }

    void event(const Event &event) override
    {
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
    void connect_thread()
    {
        const Status status = connect();
        if (status.error)
            emit("CORE_STATUS", status.message, true, true);
    }

    void emit(const std::string &name,
              const std::string &info,
              const bool is_error,
              const bool is_fatal) const
    {
        cwru_ovpn_event_callback_t callback = nullptr;
        void *context = nullptr;
        {
            std::scoped_lock lock(mutex_);
            callback = callback_;
            context = callback_context_;
        }

        if (callback)
            callback(context, name.c_str(), info.c_str(), is_error, is_fatal);
    }

    mutable std::mutex mutex_;
    cwru_ovpn_event_callback_t callback_ = nullptr;
    void *callback_context_ = nullptr;
    std::thread worker_;
    Config config_;
    ConnectionInfo last_info_;
};

} // namespace

struct cwru_ovpn_client
{
    BridgeClient impl;
};

extern "C" {

cwru_ovpn_client_t *cwru_ovpn_client_create(void)
{
    return new cwru_ovpn_client_t{};
}

void cwru_ovpn_client_destroy(cwru_ovpn_client_t *client)
{
    delete client;
}

void cwru_ovpn_client_set_event_callback(cwru_ovpn_client_t *client,
                                        cwru_ovpn_event_callback_t callback,
                                        void *context)
{
    if (client)
        client->impl.set_callback(callback, context);
}

bool cwru_ovpn_client_start(cwru_ovpn_client_t *client,
                           const char *config_content,
                           const char *gui_version,
                           const char *sso_methods,
                           char **error_message)
{
    if (!client || !config_content)
        return false;

    std::string error;
    const bool started = client->impl.start(
        config_content,
        gui_version ? gui_version : "cwru-ovpn",
        sso_methods ? sso_methods : "webauth,openurl,crtext",
        error);

    if (!started && error_message)
        *error_message = dup_string(error);

    return started;
}

void cwru_ovpn_client_stop(cwru_ovpn_client_t *client)
{
    if (client)
        client->impl.stop_and_join();
}

char *cwru_ovpn_client_copy_tun_name(const cwru_ovpn_client_t *client)
{
    return client ? client->impl.copy_tun_name() : nullptr;
}

char *cwru_ovpn_client_copy_vpn_ipv4(const cwru_ovpn_client_t *client)
{
    return client ? client->impl.copy_vpn_ipv4() : nullptr;
}

char *cwru_ovpn_client_copy_server_host(const cwru_ovpn_client_t *client)
{
    return client ? client->impl.copy_server_host() : nullptr;
}

char *cwru_ovpn_client_copy_server_ip(const cwru_ovpn_client_t *client)
{
    return client ? client->impl.copy_server_ip() : nullptr;
}

void cwru_ovpn_string_free(char *value)
{
    std::free(value);
}

} // extern "C"
