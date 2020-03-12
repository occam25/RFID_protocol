
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tag.h"

static uint64_t id =  0xE1D896E4B5A90B18;
static uint64_t pid = 0x01EEF785A7CD9001;
static uint64_t pid2= 0x025EF9877ABB1C8D;
static uint64_t active_pid;
static uint64_t k1 =  0xA1B2C3D4E5F60102;
static uint64_t k2 =  0xF1E2D3C4B5A69788;

static uint64_t n1;
static uint64_t n2;

uint8_t tag_request(uint8_t second_try, uint64_t *pid_to_use)
{
	if(pid_to_use == NULL)
		return 1;

	if(second_try)
		*pid_to_use = pid;
	else
		*pid_to_use = pid2;

	active_pid = *pid_to_use;

	return 0;

}

uint8_t tag_compute_E_F(uint64_t A, uint64_t B, uint64_t D, uint64_t *E, uint64_t *F)
{

	printf("\n### TAG: computing parameters...\n");
//	n1 = A ^ (active_pid & k1);
//	n2 = B ^ (~active_pid & k2);

	n1 = A ^ (active_pid & k1 & k2);
	n2 = B ^ (~active_pid & k2 & k1);

	uint64_t computed_D = (k1 & n2) ^ (k2 & n1);

	printf("TAG n1: \t%lX\n",n1);
	printf("TAG n2: \t%lX\n",n2);
	printf("TAG D: \t\t%lX\n",computed_D);

	if(computed_D != D)
		return 1;

	*E = (k1 ^ n1 ^ id) ^ (k2 & n2);
	*F = (k1 & n1) ^ (k2 & n2);
	pid = pid2;
	pid2 = pid2 ^ n1 ^ n2;

	printf("TAG F: \t\t%lX\n",*F);
	printf("TAG E: \t\t%lX\n",*E);
	printf("TAG ID: \t%lX\n", id);
	printf("TAG pid: \t%lX\n",pid);
	printf("TAG pid2: \t%lX\n",pid2);

	return 0;
}
