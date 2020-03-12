

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
	printf("### Getting certificate from the server...\n");
	uint8_t result;
	result = server_certificate_request(&server_certificate);
	if(result != 0){
		fprintf(stderr, "Server authentication failed!\n");
		return 1;
	}
	printf("CERT: \t\t%lX\n", server_certificate);

	// Step 2: Active Pid request
	// First try to get pid2
	printf("\n### Requesting tag's Pid...\n");
	result = tag_request(0, &active_pid);
	if(result != 0){
		fprintf(stderr, "Pid request failed\n");
		return 1;
	}
	printf("Current Pid: \t%lX\n",active_pid);

	// Step 3: Request keys to the server, generate n1 and n2 and compute A, B and D
	// Request keys
	printf("\n### Requesting keys from server...\n");
	result = server_keys_request(active_pid, server_certificate, &k1, &k2);

	if(result != 0){
		fprintf(stderr, "Keys request failed\n");
		return 1;
	}
	printf("Reader K1: \t%lX\n",k1);
	printf("Reader K2: \t%lX\n",k2);

	// Random numbers
	printf("\n### Generating random numbers...\n");
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

	printf("Reader n1: \t%lX\n",n1);
	printf("Reader n2: \t%lX\n",n2);

	// Compute A, B and D
	printf("\n### A, B and D computation...\n");
	uint64_t A;
	uint64_t B;
	uint64_t D;

	A = (active_pid & k1 & k2) ^ n1;
	B = (~active_pid & k2 & k1) ^ n2;
	D = (k1 & n2) ^ (k2 & n1);

	printf("Reader A: \t%lX\n",A);
	printf("Reader B: \t%lX\n",B);
	printf("Reader D: \t%lX\n",D);

	uint64_t E;
	uint64_t F;

	printf("Reader: sending A, B and D to the tag...\n");
	result = tag_compute_E_F(A, B, D, &E, &F);

	if(result != 0){
		printf("\nReader authentication failed\n");
		return 1;
	}

	printf("\n### Reader authentication succeeded!! Checking Tag...\n");

	uint64_t computed_F = (k1 & n1) ^ (k2 & n2);
	printf("Reader F: \t%lX\n",computed_F);

	if(computed_F != F){
		printf("Tag authentication failed\n");
		return 1;
	}

	printf("Tag authentication succeeded!\n");

	printf("\n### Computing ID and updating pids\n");

	id = E ^ k1 ^ n1 ^ (k2 & n2);
	pid = pid2;
	pid2 = pid2 ^ n1 ^ n2;

	printf("Reader ID: \t%lX\n", id);
	printf("Reader pid: \t%lX\n", pid);
	printf("Reader pid2: \t%lX\n", pid2);

	return EXIT_SUCCESS;
}
