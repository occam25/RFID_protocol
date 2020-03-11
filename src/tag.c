
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tag.h"

static uint8_t id[ID_LENGTH] = {'T', 'a', 'g', '1', '2', '\0'};
static uint8_t pid[ID_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t pid2[ID_LENGTH]= {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t k1[ID_LENGTH] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
static uint8_t k2[ID_LENGTH] = {0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6};

uint8_t tag_request(uint8_t *second_pid, uint8_t *pid_to_use, uint8_t pid_len)
{
	if(pid_to_use == NULL || pid_len != ID_LENGTH)
		return 1;

	if(second_pid == NULL)
		memcpy(pid_to_use, pid2, pid_len);
	else
		memcpy(pid_to_use, pid, pid_len);

	return 0;

}
