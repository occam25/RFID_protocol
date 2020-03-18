#include <stdint.h>
#include <stdio.h>
#include "main.h"
#include "attack.h"


t_good_aproximations good_aproximations[NUM_OF_APROXIMATIONS];

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
	uint8_t i = ITERATIONS;
	uint64_t value;

	while(i){
		trigger_new_session(0, &A, &B, &D, &E, &F);
		value = ((mask & XOR_A) ? A : 0) ^ ((mask & XOR_B) ? B : 0) ^ ((mask & XOR_D) ? D : 0) ^
				((mask & XOR_E) ? E : 0) ^ ((mask & XOR_F) ? F : 0);
		dH += hamming_distance(value, true_value);
		i--;
	};
	return (dH / 10);
}

uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask)
{
	static uint8_t index = 0;
	uint16_t dH;

	dH = compute_aproximation(true_value, mask);
	printf("0x%02X = %d\n", mask, dH);

	uint8_t result = check_aproximation(dH);
	if(result == GOOD_APROX){
		printf("Good aproximation! (0x%02X)\n", mask);
		good_aproximations[index].type = mask;
		good_aproximations[index].inv = 0;
		index++;
		return index;
	}else if(result == GOOD_APROX_INV){
		printf("Good aproximation! (inv) (~0x%02X)\n", mask);
		good_aproximations[index].type = mask;
		good_aproximations[index].inv = 1;
		index++;
		return index;
	}
	return 0;
}


