#include "cwru_openvpn3_wrapper.h"
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <dns_sd.h>
#include <poll.h>
#include <resolv.h>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <strings.h>

namespace {
struct Answers {
    cwru_address_callback_t receive;
    void *context;
    bool ipv4 = false;
    bool ipv6 = false;
    bool failed = false;
    bool more = false;
    unsigned int count = 0;
};

void address_reply(DNSServiceRef, DNSServiceFlags flags, uint32_t, DNSServiceErrorType status,
                   const char *, const sockaddr *address, uint32_t, void *context)
{
    auto &answers = *static_cast<Answers *>(context);
    answers.more = flags & kDNSServiceFlagsMoreComing;
    if (++answers.count > 256 || !address || (status != kDNSServiceErr_NoError && status != kDNSServiceErr_NoSuchRecord))
    {
        answers.failed = true;
        return;
    }
    const void *bytes;
    if (address->sa_family == AF_INET)
    {
        answers.ipv4 = true;
        bytes = &reinterpret_cast<const sockaddr_in *>(address)->sin_addr;
    }
    else if (address->sa_family == AF_INET6)
    {
        answers.ipv6 = true;
        bytes = &reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr;
    }
    else
        return;
    char text[INET6_ADDRSTRLEN];
    if (status == kDNSServiceErr_NoError && (flags & kDNSServiceFlagsAdd)
        && inet_ntop(address->sa_family, bytes, text, sizeof(text)))
        answers.receive(answers.context, text);
}
}

bool cwru_resolve_addresses(const char *host, bool dual_stack, int timeout_seconds,
                            cwru_address_callback_t callback, void *context)
{
    if (!host || !callback || timeout_seconds <= 0 || timeout_seconds > 30)
        return false;
    DNSServiceRef ref = nullptr;
    Answers answers{callback, context};
    const auto protocols = kDNSServiceProtocol_IPv4 | (dual_stack ? kDNSServiceProtocol_IPv6 : 0u);
    if (DNSServiceGetAddrInfo(&ref, 0, 0, protocols, host, address_reply, &answers) != kDNSServiceErr_NoError)
        return false;
    pollfd fd{DNSServiceRefSockFD(ref), POLLIN, 0};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    while (!answers.failed && (answers.more || !answers.ipv4 || (dual_stack && !answers.ipv6)))
    {
        const auto ms = std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (ms <= 0)
            break;
        const int status = poll(&fd, 1, static_cast<int>(ms));
        if (status < 0 && errno == EINTR)
            continue;
        if (status <= 0 || !(fd.revents & POLLIN) || DNSServiceProcessResult(ref) != kDNSServiceErr_NoError)
            break;
    }
    DNSServiceRefDeallocate(ref);
    return !answers.failed && !answers.more && answers.ipv4 && (!dual_stack || answers.ipv6);
}

bool cwru_resolve_gateway(const char *host, const char *server, int timeout_seconds,
                          cwru_address_callback_t callback, void *context)
{
    if (!host || !server || !callback || timeout_seconds <= 0 || timeout_seconds > 30)
        return false;
    union res_sockaddr_union upstream{};
    if (inet_pton(AF_INET, server, &upstream.sin.sin_addr) == 1)
    {
        upstream.sin.sin_family = AF_INET;
        upstream.sin.sin_len = sizeof(sockaddr_in);
        upstream.sin.sin_port = htons(53);
    }
    else if (inet_pton(AF_INET6, server, &upstream.sin6.sin6_addr) == 1)
    {
        upstream.sin6.sin6_family = AF_INET6;
        upstream.sin6.sin6_len = sizeof(sockaddr_in6);
        upstream.sin6.sin6_port = htons(53);
    }
    else
        return false;
    struct __res_9_state resolver{};
    if (res_ninit(&resolver) != 0)
        return false;
    res_setservers(&resolver, &upstream, 1);
    resolver.retrans = timeout_seconds;
    resolver.retry = 1;
    std::array<unsigned char, NS_MAXMSG> packet{};
    const int length = res_nquery(&resolver, host, ns_c_in, ns_t_a, packet.data(), static_cast<int>(packet.size()));
    res_ndestroy(&resolver);
    ns_msg message;
    if (length < 0 || static_cast<std::size_t>(length) > packet.size() || ns_initparse(packet.data(), length, &message) < 0)
        return false;
    char canonical[NS_MAXDNAME];
    if (strlcpy(canonical, host, sizeof(canonical)) >= sizeof(canonical))
        return false;
    const int count = ns_msg_count(message, ns_s_an);
    for (int depth = 0; depth < 16; ++depth)
    {
        bool followed = false;
        for (int i = 0; i < count; ++i)
        {
            ns_rr record;
            if (ns_parserr(&message, ns_s_an, i, &record) < 0)
                return false;
            if (ns_rr_class(record) != ns_c_in || strcasecmp(ns_rr_name(record), canonical) != 0)
                continue;
            if (ns_rr_type(record) == ns_t_cname)
            {
                const int consumed = ns_name_uncompress(packet.data(), packet.data() + length, ns_rr_rdata(record), canonical, sizeof(canonical));
                if (consumed < 0 || consumed != ns_rr_rdlen(record))
                    return false;
                followed = true;
                break;
            }
            if (ns_rr_type(record) == ns_t_a && ns_rr_rdlen(record) == sizeof(in_addr))
            {
                char text[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, ns_rr_rdata(record), text, sizeof(text)))
                    callback(context, text);
            }
        }
        if (!followed)
            return true;
    }
    return false;
}
