
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tag.h"

static uint64_t id =  0xE1D896E4B5A90B18;
static uint64_t pid = 0x01EEF785A7CD9001;
static uint64_t pid2= 0x025EF9877ABB1C8D;
static uint64_t k1 =  0xA1B2C3D4E5F60102;
static uint64_t k2 =  0xF1E2D3C4B5A69788;

uint8_t tag_request(uint8_t second_try, uint64_t *pid_to_use)
{
	if(pid_to_use == NULL)
		return 1;

	if(second_try)
		*pid_to_use = pid;
	else
		*pid_to_use = pid2;

	return 0;

}
