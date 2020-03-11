

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "server.h"
#include "tag.h"

static uint64_t id;
static uint64_t pid = 0x01EEF785A7CD9001;
static uint64_t pid2 = 0x025EF9877ABB1C8D;
static uint64_t active_pid;
static uint64_t k1;
static uint64_t k2;

static uint64_t server_certificate;

int main(void) {

	// Step 1: Server certificate request
	printf("Getting server certificate...\n");
	uint8_t result;
	result = server_certificate_request(&server_certificate);
	if(result != 0){
		fprintf(stderr, "Server authentication failed\n");
		return 1;
	}
	printf("CERT: %lX\n", server_certificate);

	// Step 2: Active Pid request
	// First try to get pid2
	printf("Requesting tag's Pid...\n");
	result = tag_request(0, &active_pid);
	if(result != 0){
		fprintf(stderr, "Pid request failed\n");
		return 1;
	}
	printf("Current Pid: %lX\n",active_pid);

	// Step 3: Request keys to the server, generate n1 and n2 and compute A, B and D
	// Request keys
	printf("Requesting keys...\n");
	result = server_keys_request(active_pid, server_certificate, &k1, &k2);

	if(result != 0){
		fprintf(stderr, "Keys request failed\n");
		return 1;
	}
	printf("K1: %lX\n",k1);
	printf("K2: %lX\n",k2);

	// Random numbers
	printf("Generating random numbers...\n");
	uint64_t n1;
	uint64_t n2;
	srand(time(NULL));
	for (int i = 0; i <8; i++){
	     int k = rand()%256;
	     if(i)
	    	 n1 <<= 8;
	     n1 |= k;
	}
	for (int i = 0; i <8; i++){
	     int k = rand()%256;
	     if(i)
	    	 n2 <<= 8;
	     n2 |= k;
	}

	printf("n1: %lX\n",n1);
	printf("n2: %lX\n",n2);

	// Compute A, B and D
	printf("A, B and D computation...\n");
	uint64_t A;
	uint64_t B;
	uint64_t D;

	A = (active_pid & k1 & k2) ^ n1;
	B = (~active_pid & k2 & k1) ^ n2;
	D = (k1 & n2) ^ (k2 & n1);

	printf("A: %lX\n",A);
	printf("B: %lX\n",B);
	printf("D: %lX\n",D);


	return EXIT_SUCCESS;
}
