

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <getopt.h>

#include "main.h"
#include "server.h"
#include "tag.h"
#include "attack.h"
#include "utils.h"

static uint64_t id;
static uint64_t pid;
static uint64_t pid2;
static uint64_t active_pid;
static uint64_t k1;
static uint64_t k2;
static uint64_t server_certificate;

static unsigned int seed;

const char *program_name;

uint8_t generate_aproximations(uint64_t true_value);
void print_usage(FILE* stream, int exit_code);

uint8_t rotate;

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

	if(rotate){
		A = (active_pid & right_rotate(k1,10) & k2) ^ n1;
		B = (~active_pid & right_rotate(k2,15) & k1) ^ n2;
	}else{
		A = (active_pid & k1 & k2) ^ n1;
		B = (~active_pid & k2 & k1) ^ n2;
	}
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

	result = tag_compute_E_F(debug, rotate, A, B, D, &E, &F);

	if(result != 0){
		printf("\nReader authentication failed\n");
		return 1;
	}

	if(debug)
		printf("\n### Reader authentication succeeded!! Checking Tag...\n");

	uint64_t computed_F;

	if(rotate)
		computed_F = (right_rotate(k1,n2) & n1) ^ (right_rotate(k2,n1) & n2);
	else
		computed_F = (k1 & n1) ^ (k2 & n2);

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

int main(int argc, char* argv[]) {

	int next_option;
	const char *short_options = "hs:u:d:ar";
	const struct option long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "secret", 1, NULL, 's' },
		{ "dhup", 1, NULL, 'u' },
		{ "dhdown", 1, NULL, 'd' },
		{ "auto", 0, NULL, 'a' },
		{ "rotate", 0, NULL, 'r' },
		{ NULL, 0, NULL, 0 }
	};
	uint64_t A;
	uint64_t B;
	uint64_t D;
	uint64_t E;
	uint64_t F;
	uint8_t result;

	const char *secret_to_reveal = "ID";
	uint8_t value;
	uint8_t auto_dh = 0;

	program_name = argv[0];
	do{
		next_option = getopt_long (argc, argv, short_options, long_options, NULL);
		switch (next_option)
		{
		case 'h':
			print_usage (stdout, 0);
			break;
		case 's':
			secret_to_reveal = optarg;
			break;
		case 'u':
			value = atoi(optarg);
			if((value >= DH_UP_MIN)&&(value <= DH_UP_MAX)){
				attack_set_dh_up_limit(value);
			}else
				print_usage (stderr, 1);
			break;
		case 'd':
			value = atoi(optarg);
			if((value >= DH_DONW_MIN)&&(value <= DH_DOWN_MAX)){
				attack_set_dh_down_limit(value);
			}else
				print_usage (stderr, 1);
			break;
		case 'a':
			attack_set_dh_up_limit(DH_UP_MAX);
			attack_set_dh_down_limit(DH_DONW_MIN);
			auto_dh = 1;
			break;
		case 'r':
			rotate = 1;
			break;
		case '?': /* The user specified an invalid option. */
			print_usage (stderr, 1);
			break;
		case -1: /* Done with options. */
			break;
		default: /* Something else: unexpected. */
			abort ();
		}
	}while (next_option != -1);

	uint64_t *secret;

	if(strcmp(secret_to_reveal, "id") == 0){
		secret = &id;
	}else if(strcmp(secret_to_reveal, "k1") == 0){
		secret = &k1;
	}else if(strcmp(secret_to_reveal, "k2") == 0){
		secret = &k2;
	}else{
		fprintf(stderr, "Invalid option: %s\n", secret_to_reveal);
		print_usage(stderr, 1);
	}

	seed = time(NULL);

	result = trigger_new_session(1, &A, &B, &D, &E, &F);

	if(result != 0){
		return 1;
	}

	// Attack
	uint64_t estimation;
	printf("\n##################################################################################################\n");
	printf("Generating good aproximations...\n");
	result = generate_aproximations(*secret);
	if(auto_dh && result != 0){
		do{
			result = attack_reduce_dh_limits();
			if(result != 0){
				printf("No good aproximations found. Aborting attack\n");
				return 1;
			}
			result = generate_aproximations(*secret);
		}while(result != 0);
		printf("Good aproximations generated with dH <= %d || dH >= %d\n", attack_get_dh_down_limit(), attack_get_dh_up_limit());
	}else if(result != 0){
		printf("No good aproximations found. Aborting attack\n");
		return 1;
	}

	uint8_t best_distance = 0xff;
	uint8_t best_local_distance = 0xff;
	time_t last = time(NULL);
	t_best_estimation best_estimation;
	do{
		// Compute new estimation
		estimation = attack_compute_estimation();
		// Compute estimation's Hamming distance
		uint8_t dH = hamming_distance(*secret, estimation);
		if(dH < best_local_distance)
			best_local_distance = dH;

		if(dH < best_distance){
			best_distance = dH;
			best_estimation.distance = dH;
			best_estimation.estimation = estimation;
			best_estimation.dh_down = attack_get_dh_down_limit();
			best_estimation.dh_up = attack_get_dh_up_limit();
			best_estimation.number_of_aproximations = attack_get_index();
		}
		printf("Estimation: %016lX Distance: %02d (best: %02d) (local best: %02d)\r", estimation, dH, best_distance, best_local_distance);
		if(dH == 1){
			printf("Only one bit missing, trying brute force\n");
			// only one bit is different, try all
//			for(int i = 0; i < 64; i++){
			for(int i = 63; i >= 0; i--){
				uint64_t tmp = estimation;
				uint8_t bit = (tmp >> i) & 0x01;
				// Negate the bit
				if(bit)
					tmp &= ~((uint64_t)1 << i);
				else
					tmp |= ((uint64_t)1 << i);
				// Compare
				if(tmp == *secret){
					estimation = tmp;
					best_estimation.estimation = tmp;
					break;
				}
			}
		}else if(dH == 2){
			printf("Only two bit missing, trying brute force\n");
			// only two bit is different, try all
			uint8_t found = 0;
			for(int i = 63; i >= 0; i--){
				uint64_t i_tmp = estimation;
				uint8_t i_bit = (i_tmp >> i) & 0x01;
				// Negate the bit
				if(i_bit)
					i_tmp &= ~((uint64_t)1 << i);
				else
					i_tmp |= ((uint64_t)1 << i);
				// Check all the other bits
				for(int j = 63; j >= 0; j--){
					uint64_t j_tmp = i_tmp;
					if(j == i)
						continue;
					uint8_t j_bit = (j_tmp >> j) & 0x01;
					// Negate the bit
					if(j_bit)
						j_tmp &= ~((uint64_t)1 << j);
					else
						j_tmp |= ((uint64_t)1 << j);
					// Compare
					if(j_tmp == *secret){
						estimation = j_tmp;
						best_estimation.estimation = j_tmp;
						found = 1;
						break;
					}
				}
				if(found)
					break;
			}
		}

		if(auto_dh && ((unsigned int)(time(NULL) - last)) > 10){
			last = time(NULL);

			// time out, recalculate aproximations
			uint8_t end = 0;
			do{
				end = attack_reduce_dh_limits();
				if(end != 0){
					printf("\nAll dh limits tested\n");
					printf("############# BEST ESTIMATION ############\n");
					printf("\t%16lX Best_dH=%d (dH <= %d || dH >= %d) - %d aproximations\n", best_estimation.estimation,
							best_estimation.distance, best_estimation.dh_down, best_estimation.dh_up,
							best_estimation.number_of_aproximations);
					break;
				}
				printf("\nBest distance for this range: %02d\n", best_local_distance);
				printf("############################# Re-generating ######################################\n");
				best_local_distance = 0xff;
				result = generate_aproximations(*secret);
			}while(result != 0);
			if(end){
				break;
			}
			printf("Good aproximations re-generated (dH <= %d || dH >= %d)\n", attack_get_dh_down_limit(), attack_get_dh_up_limit());
		}
	}while(estimation != *secret);

	putchar('\n');
	printf("Real %s: \t%lX\n", secret_to_reveal, *secret);
	printf("Estimated %s: \t%lX\n", secret_to_reveal, best_estimation.estimation);
//	printf("Distance: %d\n", hamming_distance(*secret, estimation));

	if(best_estimation.estimation == *secret)
		printf("MATCH!! \n");

	return EXIT_SUCCESS;
}


uint8_t generate_aproximations(uint64_t true_value)
{
	uint8_t index;

	attack_reset_aproximations();
	// ID
	// Search for good aproximations
	// 1. Aprox = A
	attack_try_aproximation(true_value, XOR_A);
	// 2. Aprox = B
	attack_try_aproximation(true_value, XOR_B);
	// 3. Aprox = D
	attack_try_aproximation(true_value, XOR_D);
	// 4. Aprox = E
	attack_try_aproximation(true_value, XOR_E);
	// 5. Aprox = F
	attack_try_aproximation(true_value, XOR_F);
	// 6. Aprox = A ^ B
	attack_try_aproximation(true_value, XOR_A | XOR_B);
	// 7. Aprox = A ^ D
	attack_try_aproximation(true_value, XOR_A | XOR_D);
	// 8. Aprox = A ^ E
	attack_try_aproximation(true_value, XOR_A | XOR_E);
	// 9. Aprox = A ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_F);
	// 10. Aprox = B ^ D
	attack_try_aproximation(true_value, XOR_B | XOR_D);
	// 11. Aprox = B ^ E
	attack_try_aproximation(true_value, XOR_B | XOR_E);
	// 12. Aprox = B ^ F
	attack_try_aproximation(true_value, XOR_B | XOR_F);
	// 13. Aprox = D ^ E
	attack_try_aproximation(true_value, XOR_D | XOR_E);
	// 14. Aprox = D ^ F
	attack_try_aproximation(true_value, XOR_D | XOR_F);
	// 15. Aprox = E ^ F
	attack_try_aproximation(true_value, XOR_E | XOR_F);
	// 16. Aprox = A ^ B ^ D
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D);
	// 17. Aprox = A ^ B ^ E
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_E);
	// 18. Aprox = A ^ B ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_F);
	// 19. Aprox = A ^ D ^ E
	attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_E);
	// 20. Aprox = A ^ D ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_F);
	// 21. Aprox = A ^ E ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_E | XOR_F);
	// 22. Aprox = B ^ D ^ E
	attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_E);
	// 23. Aprox = B ^ D ^ F
	attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_F);
	// 24. Aprox = B ^ E ^ F
	attack_try_aproximation(true_value, XOR_B | XOR_E | XOR_F);
	// 25. Aprox = D ^ E ^ F
	attack_try_aproximation(true_value, XOR_D | XOR_E | XOR_F);
	// 26. Aprox = A ^ B ^ D ^ E
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_E);
	// 27. Aprox = A ^ B ^ D ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_F);
	// 28. Aprox = A ^ B ^ E ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_E | XOR_F);
	// 29. Aprox = A ^ D ^ E ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_D | XOR_E | XOR_F);
	// 30. Aprox = B ^ D ^ E ^ F
	attack_try_aproximation(true_value, XOR_B | XOR_D | XOR_E | XOR_F);
	// 31. Aprox = A ^ B ^ D ^ E ^ F
	attack_try_aproximation(true_value, XOR_A | XOR_B | XOR_D | XOR_E | XOR_F);

	index = attack_get_index();
	if(index == 0)
		return 1;

	if(index % 2 == 0){
		attack_remove_worst_aproximation();
		index = attack_get_index();
	}

	for(int i = 0; i < index;i++){
		printf("Good aproximation: %c0x%02X (%02d)\n", (good_aproximations[i].inv) ? '~' : ' ', good_aproximations[i].type, good_aproximations[i].dH);
	}

	printf("Number of good aproximations: %d\n", index);

	return 0;
}

void print_usage(FILE* stream, int exit_code)
{
	fprintf (stream, "Usage: %s options\n", program_name);
	fprintf (stream,
		" -h --help \t\tDisplay this usage information.\n"
		" -s --secret \t\tSecret to attack (id, k1 or k2).\n"
		" -u --dhup \t\tdh up limit (min: %d max:%d default:%d).\n"
		" -d --dhdown \t\tdh down limit (min: %d max:%d default:%d).\n"
		" -a --auto \t\tAdapt dh range automatically.\n"
		" -r --rotate \t\tInsert some rotations to make it harder to crack.\n",
		DH_UP_MIN, DH_UP_MAX, DH_UP_LIMIT,
		DH_DONW_MIN, DH_DOWN_MAX, DH_DOWN_LIMIT);
	exit(exit_code);
}
