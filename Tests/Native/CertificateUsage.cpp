#include <openvpn/log/logsimple.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <iostream>
#include <string>
#include <vector>

int main()
{
    const auto verifies = [](const std::string &profile, const std::vector<unsigned int> &expected,
                             const std::string &expected_eku) {
        std::vector<unsigned int> ku;
        std::string eku;
        const auto options = openvpn::OptionList::parse_from_config_static(profile, nullptr);
        openvpn::KUParse::remote_cert(options, "", ku, eku);
        return ku == expected && eku == expected_eku;
    };
    if (!verifies("remote-cert-tls server", {openvpn::KUParse::KU_REQUIRED}, "TLS Web Server Authentication")
        || !verifies("remote-cert-tls client", {openvpn::KUParse::KU_REQUIRED}, "TLS Web Client Authentication")
        || !verifies("remote-cert-tls server\nremote-cert-eku 1.3.6.1.5.5.7.3.1", {openvpn::KUParse::KU_REQUIRED}, "1.3.6.1.5.5.7.3.1"))
    {
        std::cerr << "Certificate role validation failed\n";
        return 1;
    }
    return 0;
}
