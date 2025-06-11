#include "../include/core.h"

// dump in HEX, buffer 'buffer' with size 'size'
void dump_buffer(Boolean PRIORITY, Uint8_t* buffer, size_t size)
{
    Uint32_t index = 0x10;
	HDK_LOG(PRIORITY, "0x00\t\t|");
	for (size_t i = 0; i < size; i++)
	{
		if(i && !(i % 0x10))
			HDK_LOG(PRIORITY, "\n0x%x\t\t|", index += 0x10);
		HDK_LOG(PRIORITY, "%s%x ", (buffer[i] < 0x10 ? "0x0" : "0x"), (int)buffer[i]);
	}
    HDK_LOG(PRIORITY, "\n");
}

//
void raw_dump_buffer(Uint8_t* buffer, size_t size)
{
    Uint32_t index = 0x10;
	for (size_t i = 0; i < size; i++)
		printf("%s%x", (buffer[i] < 0x10 ? "0" : ""), (int)buffer[i]);
    printf("\n");
}

// allocationg a buffer with length 'size' bytes and putting 'value' in all bytes
void* Alloc(size_t size, Uint8_t value)
{
    void* __allocated_ptr = malloc(size);
    memset(__allocated_ptr, value, size);
    return __allocated_ptr;
}

// safely free out an allocated pointer
void safe_free(void* p)
{
    if (NULL != p)
    {
        free(p);
        p = NULL;
    }
    return;
}

// changing endianness of a uint8_t
Uint16_t change_endianness_16(Uint16_t n)
{
    Uint16_t ret = 0;
    Uint32_t sz = sizeof(Uint16_t);
    for (size_t i = 1; i <= sizeof(Uint16_t) >> 1; ++i)
    {
        Uint32_t shift  = (sz-i) << 3;
        Uint32_t order1 = (sizeof(Uint16_t) - sz) << 3;
        Uint32_t order2 = (sizeof(Uint16_t) - i ) << 3;
        ret |= (n & (0x00FF << order1)) << shift;
        ret |= (n & (0x00FF << order2)) >> shift;
        sz--;
    }    
	return ret;
}

// changing endianness of a uint32_t
Uint32_t change_endianness_32(Uint32_t n)
{
    Uint32_t ret = 0UL;
    Uint32_t sz = sizeof(Uint32_t);
    for (size_t i = 1; i <= sizeof(Uint32_t) >> 1; ++i)
    {
        Uint32_t shift  = (sz-i) << 3;
        Uint32_t order1 = (sizeof(Uint32_t) - sz) << 3;
        Uint32_t order2 = (sizeof(Uint32_t) - i ) << 3;
        ret |= (n & (0x000000FFUL << order1)) << shift;
        ret |= (n & (0x000000FFUL << order2)) >> shift;
        sz--;
    }    
	return ret;
}

// changing endianness of a uint64_t
Uint64_t change_endianness_64(Uint64_t n)
{
    Uint64_t ret = 0ULL;
    Uint32_t sz = sizeof(Uint64_t);
    for (size_t i = 1; i <= sizeof(Uint64_t) >> 1; ++i)
    {
        Uint32_t shift  = (sz-i) << 3;
        Uint32_t order1 = (sizeof(Uint64_t) - sz) << 3;
        Uint32_t order2 = (sizeof(Uint64_t) - i ) << 3;
        ret |= (n & (0x00000000000000FFULL << order1)) << shift;
        ret |= (n & (0x00000000000000FFULL << order2)) >> shift;
        sz--;
    }    
	return ret;
}

int slugish_compare(void* _b1, void* _b2, size_t size)
{
    Int8_t* trg = (Int8_t*)_b1;
    Int8_t* src = (Int8_t*)_b2;
    for (size_t i = 0; i < size; i++)
        if (src[i] != trg[i])
            return 0;
    return 1;    
}

void CopyData(void* trg, size_t start_offset, size_t end_offset, void* src)
{
    Int8_t* psrc = (Int8_t*)src;
    Int8_t* ptrg = (Int8_t*)trg;
    Int8_t* correct_target_buffer = &ptrg[start_offset];
    for (size_t i = 0; i < end_offset - start_offset; i++)
        correct_target_buffer[i] = (src == NULL) ? 0 : *psrc++;   
}