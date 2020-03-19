#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "main.h"
#include "attack.h"


t_good_aproximations good_aproximations[NUM_OF_APROXIMATIONS];

static uint8_t index;

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

static uint8_t check_aproximation(uint64_t value)
{
	if(value <= DH_DOWN_LIMIT){
		return GOOD_APROX;
	}else if(value >= DH_UP_LIMIT){
		return GOOD_APROX_INV;
	}
	return BAD_APROX;
}

static uint16_t compute_aproximation(uint64_t true_value, uint8_t mask)
{
	uint64_t A;
	uint64_t B;
	uint64_t D;
	uint64_t E;
	uint64_t F;
	uint16_t dH = 0;
	uint16_t i = ITERATIONS;
	uint64_t value;

	while(i){
		trigger_new_session(0, &A, &B, &D, &E, &F);
		value = ((mask & XOR_A) ? A : 0) ^ ((mask & XOR_B) ? B : 0) ^ ((mask & XOR_D) ? D : 0) ^
				((mask & XOR_E) ? E : 0) ^ ((mask & XOR_F) ? F : 0);
		dH += hamming_distance(value, true_value);
		i--;
	};
	return (dH / ITERATIONS);
}

void attack_init(void)
{
	index = 0;
}

uint8_t attack_get_index(void)
{
	return index;
}

uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask)
{

	uint16_t dH;

	if(index > NUM_OF_APROXIMATIONS - 1)
		return 0;

	dH = compute_aproximation(true_value, mask);
//	printf("0x%02X = %d\n", mask, dH);

	uint8_t result = check_aproximation(dH);
	if(result == GOOD_APROX){
//		printf("Good aproximation! (0x%02X)\n", mask);
		good_aproximations[index].type = mask;
		good_aproximations[index].inv = 0;
		index++;
		return index;
	}else if(result == GOOD_APROX_INV){
//		printf("Good aproximation! (inv) (~0x%02X)\n", mask);
		good_aproximations[index].type = mask;
		good_aproximations[index].inv = 1;
		index++;
		return index;
	}
	return 0;
}
#define SESSIONS	100
uint64_t attack_compute_estimation(void)
{
	uint64_t A;
	uint64_t B;
	uint64_t D;
	uint64_t E;
	uint64_t F;
	uint64_t value;
	uint8_t mask;

	uint16_t added_bits[64] = {};
	uint64_t estimation = 0;


	uint8_t i;
	for(int j = 0; j < SESSIONS; j++){
		trigger_new_session(0, &A, &B, &D, &E, &F);
		printf("%08lX %08lX %08lX %08lX %08lX\n", A, B, D, E, F);
		i = 0;
		while(good_aproximations[i].type != 0){
			mask = good_aproximations[i].type;
			value = ((mask & XOR_A) ? A : 0) ^ ((mask & XOR_B) ? B : 0) ^ ((mask & XOR_D) ? D : 0) ^
					((mask & XOR_E) ? E : 0) ^ ((mask & XOR_F) ? F : 0);
			if(good_aproximations[i].inv)
				value = ~value;
//			printf("Type: 0x%02X: %lX\n", mask, value);
			for(int j = 0; j < 64; j++){
				uint8_t bit = (value >> j) & 0x01;
				printf("%c ", (bit) ? '1' : '0');
				added_bits[j] += bit;
			}
			putchar('\n');
			i++;
		}
		printf("%.128s\n", "--------------------------------------------------------------------------------------------------------------------------------");
	}
	for(int j = 0; j < 64; j++){
		if(j)
			printf(" %d", added_bits[j]);
		else
			printf("%d", added_bits[j]);
	}
	putchar('\n');
	printf("N = %d\n", (i * SESSIONS)/2);
	for(int j = 0; j < 64; j++){
		uint64_t pos = 1;
		pos = pos << j;
		if(added_bits[j] >= (i * SESSIONS)/2){
			estimation |= pos; //(uint64_t)(1 << j);
			if(j == 0)
				printf("1");
			else
				printf(" 1");
		}else{
			estimation &= ~pos; //(uint64_t)(~(1 << j));
			if(j == 0)
				printf("0");
			else
				printf(" 0");
		}
	}
	putchar('\n');

	for(int j = 0; j < 64; j++){
		uint8_t bit = (estimation >> j) & 0x01;
		printf("%c ", (bit) ? '1' : '0');
	}
	putchar('\n');

	return estimation;
}

