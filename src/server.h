

#ifndef SERVER_H_
#define SERVER_H_

#define CERT_LEN		10

uint8_t server_certificate_request(uint8_t *cert, uint8_t cert_len);
uint8_t server_keys_request(uint8_t *current_pid, uint8_t current_pid_len, uint8_t *cert, uint8_t cert_len,
		uint8_t *key1, uint8_t key1_len, uint8_t *key2, uint8_t key2_len);

#endif /* SERVER_H_ */
