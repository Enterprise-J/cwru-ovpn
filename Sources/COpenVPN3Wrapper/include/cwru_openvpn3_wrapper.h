#ifndef CWRU_OPENVPN3_WRAPPER_H
#define CWRU_OPENVPN3_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cwru_ovpn_client cwru_ovpn_client_t;

typedef void (*cwru_ovpn_event_callback_t)(void *context,
                                          const char *name,
                                          const char *info,
                                          bool is_error,
                                          bool is_fatal);

cwru_ovpn_client_t *cwru_ovpn_client_create(void);
void cwru_ovpn_client_destroy(cwru_ovpn_client_t *client);

void cwru_ovpn_client_set_event_callback(cwru_ovpn_client_t *client,
                                        cwru_ovpn_event_callback_t callback,
                                        void *context);

bool cwru_ovpn_client_transport_endpoint_pending(const cwru_ovpn_client_t *client, uint64_t request_id);
bool cwru_ovpn_client_complete_transport_endpoint(cwru_ovpn_client_t *client, uint64_t request_id, bool allowed);

bool cwru_ovpn_client_start(cwru_ovpn_client_t *client,
                           const char *config_content,
                           const char *gui_version,
                           const char *sso_methods,
                           const char *server_override,
                           char **error_message);

void cwru_ovpn_client_stop(cwru_ovpn_client_t *client);
void cwru_ovpn_client_shutdown(cwru_ovpn_client_t *client);
void cwru_ovpn_client_reconnect(cwru_ovpn_client_t *client, int seconds);
bool cwru_ovpn_client_is_running(const cwru_ovpn_client_t *client);

char *cwru_ovpn_client_copy_tun_name(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_vpn_ipv4(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_vpn_ipv6(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_server_host(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_server_ip(const cwru_ovpn_client_t *client);

typedef enum cwru_ovpn_profile_option_kind {
    CWRU_OVPN_PROFILE_OPTION_DIRECTIVE,
    CWRU_OVPN_PROFILE_OPTION_BLOCK,
    CWRU_OVPN_PROFILE_OPTION_ACCESS_SERVER_METADATA,
} cwru_ovpn_profile_option_kind_t;

typedef void (*cwru_ovpn_profile_option_callback_t)(void *context,
                                                   cwru_ovpn_profile_option_kind_t kind,
                                                   const char *const *arguments,
                                                   size_t argument_count);

bool cwru_ovpn_profile_enumerate_options(const char *profile_content,
                                         cwru_ovpn_profile_option_callback_t callback,
                                         void *context,
                                         char **error_message);

bool cwru_ovpn_profile_enumerate_connection_block_options(const char *connection_block_content,
                                                          cwru_ovpn_profile_option_callback_t callback,
                                                          void *context,
                                                          char **error_message);

void cwru_ovpn_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
