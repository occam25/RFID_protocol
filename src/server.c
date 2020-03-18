

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
#include "tag.h"



static uint64_t certificate = 0x265AE8FFB113B53E;

static uint64_t pid = 0x01EEF785A7CD9001;
static uint64_t pid2= 0x025EF9877ABB1C8D;
static uint64_t k1 =  0xA1B2C3D4E5F60102;
static uint64_t k2 =  0xF1E2D3C4B5A69788;

uint8_t server_certificate_request(uint64_t *cert)
{
	if(cert == NULL)
		return 1;

	// asumimos que el reader siempre se autentica correctamente y obtiene el certificado
	*cert = certificate;
	return 0;
}

uint8_t server_keys_request(uint64_t current_pid, uint64_t cert, uint64_t *key1, uint64_t *key2)
{
	if(key1 == NULL ||key2 == NULL)
		return 1;

	if(cert != certificate)
		return 1;

	*key1 = k1;
	*key2 = k2;
	return 0;
}
