//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include "data_epoch.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/cryptochoose.hpp>

namespace {

constexpr std::size_t hkdf_digest_size = 32;
constexpr std::size_t hkdf_prefix_len = 5;
constexpr std::size_t hkdf_max_label_len = UINT8_MAX - hkdf_prefix_len;
constexpr std::size_t hkdf_max_context_len = UINT8_MAX;
constexpr std::size_t hkdf_label_buffer_size =
    sizeof(std::uint16_t) + sizeof(std::uint8_t) + hkdf_prefix_len + hkdf_max_label_len + sizeof(std::uint8_t) + hkdf_max_context_len;

} // namespace

void openvpn::ovpn_hkdf_expand(const uint8_t *secret,
                               const uint8_t *info,
                               int info_len,
                               uint8_t *out,
                               int out_len)
{
    openvpn::SSLLib::CryptoAPI::HMACContext hmac(openvpn::CryptoAlgs::SHA256, secret, hkdf_digest_size);

    /* T(0) = empty string */
    uint8_t t_prev[hkdf_digest_size];
    int t_prev_len = 0;

    for (uint8_t block = 1; (block - 1) * hkdf_digest_size < out_len; block++)
    {
        hmac.reset();

        /* calculate T(block) */
        hmac.update(t_prev, t_prev_len);
        hmac.update(info, info_len);
        hmac.update(&block, 1);
        hmac.final(t_prev);

        t_prev_len = hkdf_digest_size;

        /* Copy a full hmac output or remaining bytes */
        int out_offset = (block - 1) * hkdf_digest_size;
        int copylen = std::min(static_cast<int>(hkdf_digest_size), out_len - out_offset);

        std::memcpy(out + out_offset, t_prev, copylen);
    }
}

void openvpn::ovpn_expand_label(const uint8_t *secret, size_t secret_len, const uint8_t *label, size_t label_len, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len)
{
    if (secret_len != hkdf_digest_size)
    {
        /* Our current implementation is not a general purpose one
         * and assumes that the secret size matches the size of the
         * hash (SHA256) key */
        throw std::runtime_error("hkdf secret length mismatch");
    }

    if (out_len > UINT16_MAX || label_len > hkdf_max_label_len || context_len > hkdf_max_context_len)
    {
        throw std::runtime_error("HKDF input parameters are too large");
    }

    std::array<std::uint8_t, hkdf_label_buffer_size> hkdf_label{};
    std::size_t hkdf_label_len = 0;
    auto append = [&](const void *bytes, const std::size_t length) {
        if (length == 0)
        {
            return;
        }
        std::memcpy(hkdf_label.data() + hkdf_label_len, bytes, length);
        hkdf_label_len += length;
    };

    const std::uint16_t net_out_len = htons(static_cast<std::uint16_t>(out_len));
    append(&net_out_len, sizeof(net_out_len));

    const std::uint8_t label_len_net = static_cast<std::uint8_t>(label_len + hkdf_prefix_len);
    append(&label_len_net, sizeof(label_len_net));
    append("ovpn ", hkdf_prefix_len);
    append(label, label_len);
    const std::uint8_t context_len_net = static_cast<std::uint8_t>(context_len);

    // Preserve the existing OpenVPN label encoding order to stay wire-compatible
    // with deployed peers.
    if (context_len > 0)
    {
        append(context, context_len);
    }
    append(&context_len_net, sizeof(context_len_net));

    ovpn_hkdf_expand(secret, hkdf_label.data(), static_cast<int>(hkdf_label_len), out, static_cast<int>(out_len));
}

void openvpn::EpochKey::iterate()
{
    const uint8_t epoch_update_label[] = "datakey upd";

    /* E_N+1 = OVPN-Expand-Label(E_N, "datakey upd", "", 32) */

    decltype(keydata) new_keydata{};

    ovpn_expand_label(keydata.data(), keydata.size(), epoch_update_label, 11, nullptr, 0, new_keydata.data(), new_keydata.size());

    epoch++;
    keydata = new_keydata;
}

std::pair<openvpn::StaticKey, openvpn::StaticKey> openvpn::EpochKey::data_key(openvpn::CryptoAlgs::Type cipher)
{

    BufferAllocated data_key{key_length(cipher), BufAllocFlags::DESTRUCT_ZERO | BufAllocFlags::ARRAY};
    BufferAllocated data_iv{iv_length(cipher), BufAllocFlags::DESTRUCT_ZERO | BufAllocFlags::ARRAY};

    /* Generate data key from epoch key:
     * K_i = OVPN-Expand-Label(E_i, "data_key", "", key_size)
     * implicit_iv = OVPN-Expand-Label(E_i, "data_iv", "", implicit_iv_len)
     */

    const uint8_t epoch_key_label[] = "data_key";
    const uint8_t epoch_iv_label[] = "data_iv";

    ovpn_expand_label(keydata.data(), keydata.size(), epoch_key_label, 8, nullptr, 0, data_key.data(), data_key.size());

    ovpn_expand_label(keydata.data(), keydata.size(), epoch_iv_label, 7, nullptr, 0, data_iv.data(), data_iv.size());

    return {data_key, data_iv};
}

openvpn::EpochDataChannelCryptoContext openvpn::EpochKey::key_context(openvpn::SSLLib::Ctx libctx, openvpn::CryptoAlgs::Type cipher, int mode)
{
    auto [key, iv] = data_key(cipher);

    if (iv.size() != EpochDataChannelCryptoContext::IV_SIZE)
        throw epoch_key_exception("IV size mismatch. Expected IV size to be 12");

    EpochDataChannelCryptoContext ret;

    ret.epoch = epoch;
    ret.cipher.init(libctx, cipher, key.data(), numeric_cast<unsigned, size_t>(key.size()), mode);
    std::memcpy(ret.implicit_iv.data(), iv.data(), iv.size());

    return ret;
}

openvpn::EpochKey::EpochKey(openvpn::StaticKey key)
    : epoch(1)
{
    if (key.size() < keydata.size())
        throw epoch_key_exception("Secret key too short to create epoch key");

    std::memcpy(keydata.data(), key.data(), keydata.size());
}

void openvpn::DataChannelEpoch::generate_future_receive_keys()
{
    /* We want the number of receive keys starting with the currently used
     * keys. */
    uint16_t current_epoch_recv = decrypt_ctx.epoch;

    if (current_epoch_recv == 0)
        throw epoch_key_exception("Current receive key not initialised");

    /* Either we have not generated any future keys yet or the last
     * index is the same as our current epoch key */
    if (!future_keys.empty() && future_keys.back().epoch != receive.epoch)
        throw epoch_key_exception("Epoch key generation and future keys mismatch detected");

    /* free the keys that are not used anymore */
    for (auto it = future_keys.begin(); it != future_keys.end();)
    {
        /* Key is in the past */
        if (it->epoch <= current_epoch_recv)
        {
            it = future_keys.erase(it);
        }
        else
        {
            it++;
        }
    }

    /* regenerate the array elements at the end */
    while (future_keys.size() < future_keys_count)
    {
        receive.iterate();

        auto key_ctx = receive.key_context(libctx, cipher, openvpn::SSLLib::CryptoAPI::CipherContextAEAD::DECRYPT);

        PacketIDDataReceive pid_recv;
        pid_recv.init("Epoch receive packet ID", receive.epoch, true);

        /* Avoid using emplace_back and use push_back instead as emplace_back triggers an internal error in
         * older GCC versions used by RHEL8 and Ubuntu 20.04 */
        auto ctx = EpochDataChannelDecryptContext{std::move(key_ctx), std::move(pid_recv)};
        future_keys.push_back(std::move(ctx));
    }
}
openvpn::DataChannelEpoch::DataChannelEpoch(decltype(cipher) cipher, openvpn::StaticKey e1send, openvpn::StaticKey e1recv, SSLLib::Ctx libctx, uint16_t future_key_count)
    : cipher(cipher), libctx(libctx), future_keys_count(future_key_count), send(std::move(e1send)), receive(std::move(e1recv))
{
    future_keys.reserve(future_keys_count);

    auto key_ctx = EpochDataChannelCryptoContext{receive.key_context(libctx, cipher, openvpn::SSLLib::CryptoAPI::CipherContextAEAD::DECRYPT)};
    decrypt_ctx = EpochDataChannelDecryptContext{std::move(key_ctx)};

    generate_encrypt_ctx();
    generate_future_receive_keys();
}

void openvpn::DataChannelEpoch::iterate_send_key()
{
    if (send.epoch >= UINT16_MAX)
        throw epoch_key_exception("Send epoch at limit");

    send.iterate();
    generate_encrypt_ctx();
}

void openvpn::DataChannelEpoch::generate_encrypt_ctx()
{
    auto key_ctx = send.key_context(libctx, cipher, openvpn::SSLLib::CryptoAPI::CipherContextAEAD::ENCRYPT);
    encrypt_ctx = EpochDataChannelEncryptContext{std::move(key_ctx), PacketIDDataSend{true, send.epoch}};
}

void openvpn::DataChannelEpoch::replace_update_recv_key(std::uint16_t new_epoch, const SessionStats::Ptr &stats_arg)
{
    if (new_epoch <= decrypt_ctx.epoch)
    {
        /* the new epoch is not higher than the epoch of the current decryption key, nothing to do */
        return;
    }

    auto is_epoch =
        [new_epoch](const EpochDataChannelCryptoContext &ctx)
    {
        return ctx.epoch == new_epoch;
    };

    /* Find the key of the new epoch in future keys */
    auto fki = std::find_if(future_keys.begin(), future_keys.end(), is_epoch);

    /* we should only ever be called when we successfully decrypted/authenticated
     * a packet from a peer, ie the epoch recv key *MUST* be in that
     * array */
    if (fki == future_keys.end())
        throw epoch_key_exception("Updating to new epoch receive key that is not a valid candidate");

    /* Check if the new recv key epoch is higher than the send key epoch. If
     * yes we will replace the send key as well */
    if (send.epoch < new_epoch)
    {
        /* Update the epoch_key for send to match the current key being used.
         * This is a bit of extra work but since we are a maximum of 16
         * keys behind, a maximum 16 HMAC invocations are a small price to
         * pay for a simple implementation */
        while (send.epoch < new_epoch)
        {
            send.iterate();
        }
        generate_encrypt_ctx();
    }

    /* Replace receive key */
    retiring_decrypt_ctx = std::move(decrypt_ctx);

    decrypt_ctx = std::move(*fki);
    // Explicitly invalidate the old context
    *fki = {};

    /* Generate new future keys */
    generate_future_receive_keys();
}

openvpn::EpochDataChannelDecryptContext *
openvpn::DataChannelEpoch::lookup_decrypt_key(uint16_t epoch)
{
    /* Current decrypt key is the most likely one */
    if (decrypt_ctx.epoch == epoch)
    {
        return &decrypt_ctx;
    }
    if (retiring_decrypt_ctx.epoch > 0 && retiring_decrypt_ctx.epoch == epoch)
    {
        return &retiring_decrypt_ctx;
    }
    if (epoch > decrypt_ctx.epoch
        && epoch <= decrypt_ctx.epoch + future_keys_count)
    {
        /* If we have reached the edge of the valid keys we do not return
         * the key anymore since regenerating the new keys would move us
         * over the window of valid keys and would need all kind of
         * special casing, so we stop returning the key in this case */
        if (epoch > (UINT16_MAX - future_keys_count - 1))
        {
            return nullptr;
        }

        /* Key in the range of future keys */
        int index = epoch - (decrypt_ctx.epoch + 1);
        return &future_keys.at(index);
    }

    return nullptr;
}

void openvpn::EpochDataChannelCryptoContext::calculate_iv(uint8_t *packet_id, std::array<uint8_t, IV_SIZE> &iv_dest)
{
    /* Calculate the IV with XOR */
    for (std::size_t i = 0; i < 8; i++)
    {
        iv_dest[i] = packet_id[i] ^ implicit_iv[i];
    }
    /* copy the remaining 4 bytes directly from the implicit IV */
    std::memcpy(iv_dest.data() + 8, implicit_iv.data() + 8, IV_SIZE - 8);
}

void openvpn::DataChannelEpoch::check_send_iterate()
{
    if (send.epoch == UINT16_MAX)
    {
        /* limit of epoch keys reached, cannot move to a newer key anymore, pid writing will throw an error instead */
        return;
    }
    if (encrypt_ctx.cipher.get_usage_limit().usage_limit_reached() || encrypt_ctx.pid.at_limit())
    {
        iterate_send_key();
    }
}
