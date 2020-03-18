
#ifndef ATTACK_H_
#define ATTACK_H_

#define BAD_APROX		 0
#define GOOD_APROX		 1
#define GOOD_APROX_INV	 2
#define DH_UP_LIMIT		40
#define DH_DOWN_LIMIT	20

#define ITERATIONS		  10
#define XOR_A			0x01
#define XOR_B			0x02
#define XOR_D			0x04
#define XOR_E			0x08
#define XOR_F			0x10

#define NUM_OF_APROXIMATIONS	9

typedef struct good_aproxs {
	uint8_t type;
	uint8_t inv;
}t_good_aproximations;

extern t_good_aproximations good_aproximations[9];

uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask);

#endif /* ATTACK_H_ */
