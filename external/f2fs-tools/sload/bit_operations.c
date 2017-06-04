#include <f2fs_fs.h>
#include "bit_operations.h"

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define min(x, y) ({           \
    typeof(x) _min1 = (x);     \
    typeof(y) _min2 = (y);     \
    (void) (&_min1 == &_min2); \
    _min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({                \
    typeof(x) _max1 = (x);          \
    typeof(y) _max2 = (y);          \
    (void) (&_max1 == &_max2);      \
   _max1 > _max2 ? _max1 : _max2; })

#define BITS_PER_BYTE 8
#define BITMAP_FIRST_BYTE_MASK(start) (0xff << ((start) & (BITS_PER_BYTE - 1)))

int set_bit(unsigned int nr, void *addr)
{
	int mask, retval;
	unsigned char *ADDR = (unsigned char *)addr;

	ADDR += nr >> 3;
	mask = 1 << ((nr & 0x07));
	retval = mask & *ADDR;
	*ADDR |= mask;
	return retval;
}

int clear_bit(unsigned int nr, void *addr)
{
	int mask, retval;
	unsigned char *ADDR = (unsigned char *)addr;

	ADDR += nr >> 3;
	mask = 1 << ((nr & 0x07));
	retval = mask & *ADDR;
	*ADDR &= ~mask;
	return retval;
}

int test_bit(unsigned int nr, const void *addr)
{
	const __u32 *p = (const __u32 *)addr;

	nr = nr ^ 0;

	return ((1 << (nr & 31)) & (p[nr >> 5])) != 0;
}

static unsigned long __ffs(unsigned char byte)
{
	unsigned long num = 0;

	if ((byte & 0xf) == 0) {
		num += 4;
		byte >>= 4;
	}
	if ((byte & 0x3) == 0) {
		num += 2;
		byte >>= 2;
	}
	if ((byte & 0x1) == 0) {
		num += 1;
	}
	return num;
}

static unsigned long _find_next_bit_le_sload(const char *addr,
                unsigned long nbits, unsigned long start, char invert)
{
    char tmp;
    if (!nbits || start >= nbits)
        return nbits;

    tmp = addr[start / BITS_PER_BYTE] ^ invert;

	tmp &= BITMAP_FIRST_BYTE_MASK(start);
    start = round_down(start, BITS_PER_BYTE);

    while (!tmp) {
        start += BITS_PER_BYTE;
        if (start >= nbits)
            return nbits;
        tmp = addr[start / BITS_PER_BYTE] ^ invert;
    }
    return min(start + __ffs(tmp), nbits);
}

unsigned long find_next_bit_le_sload(const char *addr, unsigned long size,
				unsigned long offset)
{
	return _find_next_bit_le_sload(addr, size, offset, 0);
}


unsigned long find_next_zero_bit_le_sload(const char *addr, unsigned long size,
				unsigned long offset)
{
	return _find_next_bit_le_sload(addr, size, offset, 0xff);
}

/**
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 **/
int test_and_set_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (nr & 0x7);
	ret = mask & *addr;
	*addr |= mask;
	return ret;
}

void change_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (nr & 0x7);
	*addr ^= mask;
}

int f2fs_test_and_set_bit(unsigned int nr, char *addr)
{
    int mask;
    int ret;

    addr += (nr >> 3);
    mask = 1 << (7 - (nr & 0x07));
    ret = mask & *addr;
    *addr |= mask;
    return ret;
}

int f2fs_test_and_clear_bit(unsigned int nr, char *addr)
{
    int mask;
    int ret;

    addr += (nr >> 3);
    mask = 1 << (7 - (nr & 0x07));
    ret = mask & *addr;
    *addr &= ~mask;
    return ret;
}

