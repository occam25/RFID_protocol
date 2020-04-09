
#ifndef ATTACK_H_
#define ATTACK_H_

#define BAD_APROX		 0
#define GOOD_APROX		 1
#define GOOD_APROX_INV	 2
#define DH_UP_LIMIT		39 //40
#define DH_DOWN_LIMIT	25 //24
#define DH_UP_MIN		33
#define DH_UP_MAX		63
#define DH_DONW_MIN		1
#define DH_DOWN_MAX		31

#define ITERATIONS		100
#define XOR_A			0x01
#define XOR_B			0x02
#define XOR_D			0x04
#define XOR_E			0x08
#define XOR_F			0x10

#define NUM_OF_APROXIMATIONS	32

typedef struct s_good_aproxs {
	uint8_t type;
	uint8_t inv;
	uint8_t dH;
}t_good_aproximations;

typedef struct s_best_estimation {
	uint8_t distance;
	uint8_t dh_up;
	uint8_t dh_down;
	uint64_t estimation;
	uint8_t number_of_aproximations;
}t_best_estimation;


extern t_good_aproximations good_aproximations[NUM_OF_APROXIMATIONS];

void attack_reset_aproximations(void);
uint8_t attack_get_index(void);
uint8_t attack_try_aproximation(uint64_t true_value, uint8_t mask);
uint64_t attack_compute_estimation(void);
void attack_set_dh_up_limit(uint8_t value);
void attack_set_dh_down_limit(uint8_t value);
uint8_t attack_get_dh_up_limit(void);
uint8_t attack_get_dh_down_limit(void);
uint8_t attack_reduce_dh_limits(void);
void attack_remove_worst_aproximation(void);

#endif /* ATTACK_H_ */
