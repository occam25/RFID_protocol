

#ifndef SERVER_H_
#define SERVER_H_

uint8_t server_certificate_request(uint64_t *cert);
uint8_t server_keys_request(uint64_t current_pid, uint64_t cert, uint64_t *key1, uint64_t *key2);

#endif /* SERVER_H_ */
