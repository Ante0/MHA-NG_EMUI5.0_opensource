#ifndef _BIT_OPERATIONS_H_
#define _BIT_OPERATIONS_H_

int test_and_set_bit(unsigned int nr, char *addr);
void change_bit(unsigned int nr, char *addr);
unsigned long find_next_bit_le_sload(const char *addr, unsigned long size,
                unsigned long offset);
unsigned long find_next_zero_bit_le_sload(const char *addr, unsigned long size,
                unsigned long offset);

int f2fs_test_and_set_bit(unsigned int nr, char *addr);
int f2fs_test_and_clear_bit(unsigned int nr, char *addr);

int set_bit(unsigned int nr, void *addr);
int clear_bit(unsigned int nr, void *addr);
int test_bit(unsigned int nr, const void *addr);

#endif
