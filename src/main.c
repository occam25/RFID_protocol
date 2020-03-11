

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "server.h"
#include "tag.h"

static uint8_t id[ID_LENGTH];
static uint8_t pid[ID_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t pid2[ID_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t active_pid[ID_LENGTH];
static uint8_t k1[ID_LENGTH];
static uint8_t k2[ID_LENGTH];

static uint8_t server_certificate[CERT_LEN];

int main(void) {
//	printf("ID: %s\n", id);
//	printf("K1:   0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
//			k1[0], k1[1], k1[2], k1[3], k1[4], k1[5]);
//	printf("K2:   0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
//			k2[0], k2[1], k2[2], k2[3], k2[4], k2[5]);
//	printf("Pid:  0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
//			pid[0], pid[1], pid[2], pid[3], pid[4], pid[5]);
//	printf("Pid2: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
//			pid2[0], pid2[1], pid2[2], pid2[3], pid2[4], pid2[5]);

	// Step 1: Server certificate request
	printf("Getting server certificate...\n");
	uint8_t result;
	result = server_certificate_request(server_certificate, sizeof(server_certificate)/sizeof(server_certificate[0]));
	if(result != 0){
		fprintf(stderr, "Server authentication failed\n");
		return 1;
	}
	printf("CERT: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
			server_certificate[0], server_certificate[1], server_certificate[2],
			server_certificate[3], server_certificate[4], server_certificate[5]);

	// Step 2: Active Pid request
	// First try to get pid2
	printf("Requesting tag's Pid...\n");
	result = tag_request(NULL, active_pid, sizeof(active_pid)/sizeof(active_pid[0]));
	if(result != 0){
		fprintf(stderr, "Pid request failed\n");
		return 1;
	}
	printf("Current Pid: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
			active_pid[0], active_pid[1], active_pid[2], active_pid[3], active_pid[4], active_pid[5]);

	// Step 3: Request keys to the server, generate n1 and n2 and compute A, B and D
	// Request keys
	printf("Requesting keys...\n");
	result = server_keys_request(active_pid, sizeof(active_pid)/sizeof(active_pid[0]),
			server_certificate, sizeof(server_certificate)/sizeof(server_certificate[0]),
			k1, sizeof(k1)/sizeof(k1[0]), k2, sizeof(k2)/sizeof(k2[0]));

	if(result != 0){
		fprintf(stderr, "Keys request failed\n");
		return 1;
	}
	printf("K1:   0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
			k1[0], k1[1], k1[2], k1[3], k1[4], k1[5]);
	printf("K2:   0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
			k2[0], k2[1], k2[2], k2[3], k2[4], k2[5]);

	return EXIT_SUCCESS;
}
