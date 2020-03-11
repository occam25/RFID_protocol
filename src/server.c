

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
#include "tag.h"



static uint8_t certificate[CERT_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

static uint8_t pid[ID_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t pid2[ID_LENGTH]= {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t k1[ID_LENGTH] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
static uint8_t k2[ID_LENGTH] = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6};

uint8_t server_certificate_request(uint8_t *cert, uint8_t cert_len)
{
	if(cert == NULL || cert_len != CERT_LEN)
		return 1;

	// asumimos que el reader siempre se autentica correctamente y obtiene el certificado
	memcpy(cert, certificate, cert_len);
	return 0;
}

uint8_t server_keys_request(uint8_t *current_pid, uint8_t current_pid_len, uint8_t *cert, uint8_t cert_len,
		uint8_t *key1, uint8_t key1_len, uint8_t *key2, uint8_t key2_len)
{
	if(current_pid == NULL || current_pid_len != ID_LENGTH || cert == NULL || cert_len != CERT_LEN ||
			key1 == NULL || key1_len != ID_LENGTH || key2 == NULL || key2_len != ID_LENGTH)
		return 1;

	if((memcmp(certificate, cert, CERT_LEN) != 0)||((memcmp(pid, current_pid, ID_LENGTH) != 0)&&(memcmp(pid2, current_pid, ID_LENGTH) != 0)))
		return 1;

	memcpy(key1, k1, key1_len);
	memcpy(key2, k2, key2_len);
	return 0;
}
