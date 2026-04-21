#ifndef CWRU_OPENVPN3_WRAPPER_H
#define CWRU_OPENVPN3_WRAPPER_H

#include <stdbool.h>

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

bool cwru_ovpn_client_start(cwru_ovpn_client_t *client,
                           const char *config_content,
                           const char *gui_version,
                           const char *sso_methods,
                           char **error_message);

void cwru_ovpn_client_stop(cwru_ovpn_client_t *client);

char *cwru_ovpn_client_copy_tun_name(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_vpn_ipv4(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_server_host(const cwru_ovpn_client_t *client);
char *cwru_ovpn_client_copy_server_ip(const cwru_ovpn_client_t *client);

void cwru_ovpn_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
