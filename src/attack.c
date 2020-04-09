#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "main.h"
#include "attack.h"


t_good_aproximations good_aproximations[NUM_OF_APROXIMATIONS];

static uint8_t idx;
static uint8_t dh_up_limit = DH_UP_LIMIT;
static uint8_t dh_down_limit = DH_DOWN_LIMIT;

void attack_set_dh_up_limit(uint8_t value)
{
	dh_up_limit = value;
}

void attack_set_dh_down_limit(uint8_t value)
{
	dh_down_limit = value;
}

uint8_t attack_reduce_dh_limits(void)
{
	if((dh_up_limit == DH_UP_MIN)&&(dh_down_limit == DH_DOWN_MAX))
		return 1;

	if(dh_up_limit > DH_UP_MIN)
		dh_up_limit--;

	if(dh_down_limit < DH_DOWN_MAX)
		dh_down_limit++;

	return 0;
}

uint8_t attack_get_dh_up_limit(void)
{
	return dh_up_limit;
}

uint8_t attack_get_dh_down_limit(void)
{
	return dh_down_limit;
}

static uint8_t hamming_distance(uint64_t a, uint64_t b)
{
    uint64_t x = a ^ b;
    uint8_t setBits = 0;

    while(x > 0) {
        setBits += x & 0x01;
        x >>= 1;
    }

    return setBits;
}

static uint8_t check_aproximation(uint64_t value)
{
	if(value <= dh_down_limit){
		return GOOD_APROX;
	}else if(value >= dh_up_limit){
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
	uint32_t dH = 0;
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

void attack_reset_aproximations(void)
{
	idx = 0;
	memset(good_aproximations, 0, sizeof(good_aproximations));
}

uint8_t attack_get_index(void)
{
	return idx;
}

uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask)
{
	uint16_t dH;

	if(idx > NUM_OF_APROXIMATIONS - 1)
		return 0;

	dH = compute_aproximation(true_value, mask);
//	printf("0x%02X = %d\n", mask, dH);

	uint8_t result = check_aproximation(dH);
	if(result == GOOD_APROX){
//		printf("Good aproximation! (0x%02X)\n", mask);
		good_aproximations[idx].type = mask;
		good_aproximations[idx].inv = 0;
		good_aproximations[idx].dH = dH;
		idx++;
		return idx;
	}else if(result == GOOD_APROX_INV){
//		printf("Good aproximation! (inv) (~0x%02X)\n", mask);
		good_aproximations[idx].type = mask;
		good_aproximations[idx].inv = 1;
		good_aproximations[idx].dH = 64 - dH;
		idx++;
		return idx;
	}
	return 0;
}

int compare(const void *v1, const void *v2)
{
    const t_good_aproximations *p1 = (t_good_aproximations *)v1;
    const t_good_aproximations *p2 = (t_good_aproximations *)v2;
    if (p1->dH < p2->dH)
        return -1;
    else if (p1->dH > p2->dH)
        return 1;
    else
        return 0;
}

void attack_remove_worst_aproximation(void)
{

	qsort(good_aproximations, idx, sizeof(good_aproximations[0]), compare);

	good_aproximations[idx-1].type = 0;
	idx--;

}

#define SESSIONS			100
#undef DEBUG_ESTIMATION
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
#ifdef DEBUG_ESTIMATION
		printf("%08lX %08lX %08lX %08lX %08lX\n", A, B, D, E, F);
#endif
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
#ifdef DEBUG_ESTIMATION
				printf("%c ", (bit) ? '1' : '0');
#endif
				added_bits[j] += bit;
			}
#ifdef DEBUG_ESTIMATION
			putchar('\n');
#endif
			i++;
		}
#ifdef DEBUG_ESTIMATION
		printf("%.128s\n", "--------------------------------------------------------------------------------------------------------------------------------");
#endif
	}
#ifdef DEBUG_ESTIMATION
	for(int j = 0; j < 64; j++){
		if(j)
			printf(" %d", added_bits[j]);
		else
			printf("%d", added_bits[j]);
	}
	putchar('\n');
	printf("N = %d\n", (i * SESSIONS)/2);
#endif
	for(int j = 0; j < 64; j++){
		uint64_t pos = 1;
		pos = pos << j;
		if(added_bits[j] >= (i * SESSIONS)/2){
			estimation |= pos; //(uint64_t)(1 << j);
#ifdef DEBUG_ESTIMATION
			if(j == 0)
				printf("1");
			else
				printf(" 1");
#endif
		}else{
			estimation &= ~pos; //(uint64_t)(~(1 << j));
#ifdef DEBUG_ESTIMATION
			if(j == 0)
				printf("0");
			else
				printf(" 0");
#endif
		}
	}
#ifdef DEBUG_ESTIMATION
	putchar('\n');
	for(int j = 0; j < 64; j++){
		uint8_t bit = (estimation >> j) & 0x01;
		printf("%c ", (bit) ? '1' : '0');
	}
	putchar('\n');
#endif
	return estimation;
}

