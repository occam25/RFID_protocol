
#ifndef ATTACK_H_
#define ATTACK_H_

#define BAD_APROX		 0
#define GOOD_APROX		 1
#define GOOD_APROX_INV	 2
#define DH_UP_LIMIT		40
#define DH_DOWN_LIMIT	24

#define ITERATIONS		1000
#define XOR_A			0x01
#define XOR_B			0x02
#define XOR_D			0x04
#define XOR_E			0x08
#define XOR_F			0x10

#define NUM_OF_APROXIMATIONS	32

typedef struct good_aproxs {
	uint8_t type;
	uint8_t inv;
}t_good_aproximations;

extern t_good_aproximations good_aproximations[NUM_OF_APROXIMATIONS];

void attack_init(void);
uint8_t attack_get_index(void);
uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask);
uint64_t attack_compute_estimation(void);

#endif /* ATTACK_H_ */
