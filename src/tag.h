
#ifndef TAG_H_
#define TAG_H_

#include <stdint.h>

#define ID_LENGTH		6

//extern uint8_t id[ID_LENGTH];
//extern uint8_t pid[ID_LENGTH];
//extern uint8_t pid2[ID_LENGTH];
//extern uint8_t k1[ID_LENGTH];
//extern uint8_t k2[ID_LENGTH];

uint8_t tag_request(uint8_t *second_pid, uint8_t *pid_to_use, uint8_t pid_len);

#endif /* TAG_H_ */
