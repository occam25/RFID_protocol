
#include "utils.h"

uint64_t right_rotate(uint64_t value, uint8_t r)
{
	for(int i = 0; i < r; i++){
		uint8_t bit = value & 0x01;
		value >>= 1;
		if(bit){
			value |= ((uint64_t)1<<63);
		}
	}
	return value;
}
