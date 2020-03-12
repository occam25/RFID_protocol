
#ifndef TAG_H_
#define TAG_H_

#include <stdint.h>


uint8_t tag_request(uint8_t second_try, uint64_t *pid_to_use);
uint8_t tag_compute_E_F(uint64_t A, uint64_t B, uint64_t D, uint64_t *E, uint64_t *F);

#endif /* TAG_H_ */
