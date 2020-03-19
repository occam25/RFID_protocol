

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "main.h"
#include "server.h"
#include "tag.h"
#include "attack.h"


static uint64_t id;
static uint64_t pid;
static uint64_t pid2;
static uint64_t active_pid;
static uint64_t k1;
static uint64_t k2;
static uint64_t server_certificate;

static unsigned int seed;

uint8_t do_attack(uint64_t true_value, uint64_t *estimation);

uint8_t trigger_new_session(uint8_t debug, uint64_t *a, uint64_t *b, uint64_t *d, uint64_t *e, uint64_t *f)
{
	// Step 1: Server certificate request
	if(debug)
		printf("### Getting certificate from the server...\n");
	uint8_t result;
	result = server_certificate_request(&server_certificate);
	if(result != 0){
		fprintf(stderr, "Server authentication failed!\n");
		return 1;
	}
	if(debug)
		printf("CERT: \t\t%lX\n", server_certificate);

	// Step 2: Active Pid request
	// First try to get pid2
	if(debug)
		printf("\n### Requesting tag's Pid...\n");
	result = tag_request(0, &active_pid);
	if(result != 0){
		fprintf(stderr, "Pid request failed\n");
		return 1;
	}
	pid2 = active_pid;
	if(debug)
		printf("Current Pid: \t%lX\n",active_pid);

	// Step 3: Request keys to the server, generate n1 and n2 and compute A, B and D
	// Request keys
	if(debug)
		printf("\n### Requesting keys from server...\n");

	result = server_keys_request(active_pid, server_certificate, &k1, &k2);

	if(result != 0){
		fprintf(stderr, "Keys request failed\n");
		return 1;
	}
	if(debug){
		printf("Reader K1: \t%lX\n",k1);
		printf("Reader K2: \t%lX\n",k2);
	}

	// Random numbers
	if(debug)
		printf("\n### Generating random numbers...\n");

	uint64_t n1;
	uint64_t n2;
	seed += 5;
	srand(seed);
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

	if(debug){
		printf("Reader n1: \t%lX\n",n1);
		printf("Reader n2: \t%lX\n",n2);
	}

	// Compute A, B and D
	if(debug)
		printf("\n### A, B and D computation...\n");

	uint64_t A;
	uint64_t B;
	uint64_t D;

	A = (active_pid & k1 & k2) ^ n1;
	B = (~active_pid & k2 & k1) ^ n2;
	D = (k1 & n2) ^ (k2 & n1);

	if(debug){
		printf("Reader A: \t%lX\n",A);
		printf("Reader B: \t%lX\n",B);
		printf("Reader D: \t%lX\n",D);
	}

	uint64_t E;
	uint64_t F;

	if(debug)
		printf("Reader: sending A, B and D to the tag...\n");

	result = tag_compute_E_F(debug, A, B, D, &E, &F);

	if(result != 0){
		printf("\nReader authentication failed\n");
		return 1;
	}

	if(debug)
		printf("\n### Reader authentication succeeded!! Checking Tag...\n");

	uint64_t computed_F = (k1 & n1) ^ (k2 & n2);
	if(debug)
		printf("Reader F: \t%lX\n",computed_F);

	if(computed_F != F){
		printf("Tag authentication failed\n");
		return 1;
	}

	if(debug){
		printf("Tag authentication succeeded!\n");
		printf("\n### Computing ID and updating pids\n");
	}

	id = E ^ k1 ^ n1 ^ (k2 & n2);
	pid = pid2;
	pid2 = pid2 ^ n1 ^ n2;

	if(debug){
		printf("Reader ID: \t%lX\n", id);
		printf("Reader pid: \t%lX\n", pid);
		printf("Reader pid2: \t%lX\n", pid2);
	}

	*a = A;
	*b = B;
	*d = D;
	*e = E;
	*f = F;

	return 0;
}

static uint8_t hamming_distance(uint64_t a, uint64_t b)
{
    uint64_t x = a ^ b;
    uint8_t setBits = 0;

    while(x > 0) {
        setBits += x & 1;
        x >>= 1;
    }

    return setBits;
}

int main(void) {

	uint64_t A;
	uint64_t B;
	uint64_t D;
	uint64_t E;
	uint64_t F;

	uint8_t result;

	seed = time(NULL);

	result = trigger_new_session(1, &A, &B, &D, &E, &F);

	if(result != 0){
		return 1;
	}

	// Attack
	uint64_t estimation;

	do{
		result = do_attack(id, &estimation);
	}while(result != 0);

	printf("Real ID: \t%lX\n", id);
	printf("Estimated ID: \t%lX\n", estimation);
	printf("Distance: %d\n", hamming_distance(id, estimation));

	if(estimation == id)
		printf("MATCH!! \n");

	return EXIT_SUCCESS;
}

uint8_t do_attack(uint64_t true_value, uint64_t *estimation)
{
	uint8_t index;
	// ID
	// Search for good aproximations
	// 1. Aprox = A
	index = attack_try_aproximation(true_value, XOR_A);
	// 2. Aprox = B
	index = attack_try_aproximation(true_value, XOR_B);
	// 3. Aprox = D
	index = attack_try_aproximation(true_value, XOR_D);
	// 4. Aprox = E
	index = attack_try_aproximation(true_value, XOR_E);
	// 5. Aprox = F
	index = attack_try_aproximation(true_value, XOR_F);
	// 6. Aprox = A ^ B
	index = attack_try_aproximation(true_value, XOR_A | XOR_B);
	// 7. Aprox = A ^ D
	index = attack_try_aproximation(true_value, XOR_A | XOR_D);
	// 8. Aprox = A ^ E
	index = attack_try_aproximation(true_value, XOR_A | XOR_E);
	// 9. Aprox = A ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_F);
	// 10. Aprox = B ^ D
	index = attack_try_aproximation(true_value, XOR_B | XOR_D);
	// 11. Aprox = B ^ E
	index = attack_try_aproximation(true_value, XOR_B | XOR_E);
	// 12. Aprox = B ^ F
	index = attack_try_aproximation(true_value, XOR_B | XOR_F);
	// 13. Aprox = D ^ E
	index = attack_try_aproximation(true_value, XOR_D | XOR_E);
	// 14. Aprox = D ^ F
	index = attack_try_aproximation(true_value, XOR_D | XOR_F);
	// 15. Aprox = E ^ F
	index = attack_try_aproximation(true_value, XOR_E | XOR_F);
	// 16. Aprox = A ^ B ^ D
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D);
	// 17. Aprox = A ^ B ^ E
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_E);
	// 18. Aprox = A ^ B ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_F);
	// 19. Aprox = A ^ D ^ E
	index = attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_E);
	// 20. Aprox = A ^ D ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_F);
	// 21. Aprox = A ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_E | XOR_F);
	// 22. Aprox = B ^ D ^ E
	index = attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_E);
	// 23. Aprox = B ^ D ^ F
	index = attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_F);
	// 24. Aprox = B ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_B | XOR_E | XOR_F);
	// 25. Aprox = D ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_D | XOR_E | XOR_F);
	// 26. Aprox = A ^ B ^ D ^ E
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_E);
	// 27. Aprox = A ^ B ^ D ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_F);
	// 28. Aprox = A ^ B ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_E | XOR_F);
	// 29. Aprox = A ^ D ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_E | XOR_F);
	// 30. Aprox = B ^ D ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_E | XOR_F);
	// 31. Aprox = A ^ B ^ D ^ E ^ F
	index = attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_E | XOR_F);

	index = attack_get_index();
	for(int i = 0; i < index; i++){
		printf("Good aproximation %s0x%02X\n", (good_aproximations[i].inv == 1) ? "~" : " ", good_aproximations[i].type);
	}

	if(index == 0)
		return 1;

	*estimation = attack_compute_estimation();

	return 0;
}

