/* XMRig
 * Copyright (c) 2018      Lee Clagett              <https://github.com/vtnerd>
 * Copyright (c) 2018-2019 tevador                  <tevador@gmail.com>
 * Copyright (c) 2000      Transmeta Corporation    <https://github.com/intel/msr-tools>
 * Copyright (c) 2004-2008 H. Peter Anvin           <https://github.com/intel/msr-tools>
 * Copyright (c) 2018-2021 SChernykh                <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig                    <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto/astrobwt/AstroBWT.h"
#include "backend/cpu/Cpu.h"
#include "base/crypto/sha3.h"
#include "base/tools/bswap_64.h"
#include "crypto/cn/CryptoNight.h"


#include <limits>


#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>


constexpr int STAGE1_SIZE = 147253;
constexpr int ALLOCATION_SIZE = (STAGE1_SIZE + 1048576) + (128 - (STAGE1_SIZE & 63));

constexpr int COUNTING_SORT_BITS = 10;
constexpr int COUNTING_SORT_SIZE = 1 << COUNTING_SORT_BITS;

static bool astrobwtInitialized = false;


constexpr int ITEM_SIZE = 6, ITEMS_PER_BUCKET = 256*11;
constexpr int bucket_size = ITEMS_PER_BUCKET*ITEM_SIZE;
const __m256i bucket_0123 = _mm256_set_epi64x(bucket_size*3, bucket_size*2, bucket_size, 0);
const __m256i _4buckets = _mm256_set1_epi64x(bucket_size*4);


#define MOVB(src, dest) asm ("movb %0, %1" : /* No outputs */ : "r" (src), "r" (dest));

#ifdef ASTROBWT_AVX2
static bool hasAVX2 = false;

extern "C"
#ifndef _MSC_VER
__attribute__((ms_abi))
#endif
void SHA3_256_AVX2_ASM(const void* in, size_t inBytes, void* out);

#endif

#ifdef XMRIG_ARM
extern "C" {
#include "salsa20_ref/ecrypt-sync.h"
}

static void Salsa20_XORKeyStream(const void* key, void* output, size_t size)
{
	uint8_t iv[8] = {};
	ECRYPT_ctx ctx;
	ECRYPT_keysetup(&ctx, static_cast<const uint8_t*>(key), 256, 64);
	ECRYPT_ivsetup(&ctx, iv);
	ECRYPT_keystream_bytes(&ctx, static_cast<uint8_t*>(output), size);
	memset(static_cast<uint8_t*>(output) - 16, 0, 16);
	memset(static_cast<uint8_t*>(output) + size, 0, 16);
}
#else
#include "Salsa20.hpp"

static void Salsa20_XORKeyStream(const void* key, void* output, size_t size)
{
	const uint64_t iv = 0;
	ZeroTier::Salsa20 s(key, &iv);
	s.XORKeyStream(output, static_cast<uint32_t>(size));
	memset(static_cast<uint8_t*>(output) - 16, 0, 16);
	memset(static_cast<uint8_t*>(output) + size, 0, 16);
}

extern "C" int salsa20_stream_avx2(void* c, uint64_t clen, const void* iv, const void* key);

static void Salsa20_XORKeyStream_AVX256(const void* key, void* output, size_t size)
{
	const uint64_t iv = 0;
	salsa20_stream_avx2(output, size, &iv, key);
	memset(static_cast<uint8_t*>(output) - 16, 0, 16);
	memset(static_cast<uint8_t*>(output) + size, 0, 16);
}
#endif

template <class T>
__attribute__((always_inline)) inline T& forceRegister(const T &value) {
    asm volatile("" : "+r"(const_cast<T&>(value)));
    return const_cast<T&>(value);
}

static inline bool smaller(const uint8_t* v, uint64_t a, uint64_t b)
{
	const uint64_t value_a = a >> 21;
	const uint64_t value_b = b >> 21;

	if (value_a < value_b) {
		return true;
	}

	if (value_a > value_b) {
		return false;
	}

	a &= (1 << 21) - 1;
	b &= (1 << 21) - 1;

	if (a == b) {
		return false;
	}

	const uint64_t data_a = bswap_64(*reinterpret_cast<const uint64_t*>(v + a + 5));
	const uint64_t data_b = bswap_64(*reinterpret_cast<const uint64_t*>(v + b + 5));
	return (data_a < data_b);
}

void sort_indices(uint32_t N, const uint8_t* v, uint64_t* indices, uint64_t* tmp_indices)
{
	uint32_t counters[2][COUNTING_SORT_SIZE] = {};

	{
#define ITER(X) \
		do { \
			const uint64_t k = bswap_64(*reinterpret_cast<const uint64_t*>(v + i + X)); \
			++counters[0][(k >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)]; \
			++counters[1][k >> (64 - COUNTING_SORT_BITS)]; \
		} while (0)

		uint32_t i = 0;
		const uint32_t n = N - 15;
		for (; i < n; i += 16) {
			ITER(0); ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7);
			ITER(8); ITER(9); ITER(10); ITER(11); ITER(12); ITER(13); ITER(14); ITER(15);
		}
		for (; i < N; ++i) {
			ITER(0);
		}

#undef ITER
	}

	uint32_t prev[2] = { counters[0][0], counters[1][0] };
	counters[0][0] = prev[0] - 1;
	counters[1][0] = prev[1] - 1;
	for (int i = 1; i < COUNTING_SORT_SIZE; ++i)
	{
		const uint32_t cur[2] = { counters[0][i] + prev[0], counters[1][i] + prev[1] };
		counters[0][i] = cur[0] - 1;
		counters[1][i] = cur[1] - 1;
		prev[0] = cur[0];
		prev[1] = cur[1];
	}

	{
#define ITER(X) \
		do { \
			const uint64_t k = bswap_64(*reinterpret_cast<const uint64_t*>(v + (i - X))); \
			tmp_indices[counters[0][(k >> (64 - COUNTING_SORT_BITS * 2)) & (COUNTING_SORT_SIZE - 1)]--] = (k & (static_cast<uint64_t>(-1) << 21)) | (i - X); \
		} while (0)

		uint32_t i = N;
		for (; i >= 8; i -= 8) {
			ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7); ITER(8);
		}
		for (; i > 0; --i) {
			ITER(1);
		}

#undef ITER
	}

	{
#define ITER(X) \
		do { \
			const uint64_t data = tmp_indices[i - X]; \
			indices[counters[1][data >> (64 - COUNTING_SORT_BITS)]--] = data; \
		} while (0)

		uint32_t i = N;
		for (; i >= 8; i -= 8) {
			ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7); ITER(8);
		}
		for (; i > 0; --i) {
			ITER(1);
		}

#undef ITER
	}

	uint64_t prev_t = indices[0];
	for (uint32_t i = 1; i < N; ++i)
	{
		uint64_t t = indices[i];
		if (smaller(v, t, prev_t))
		{
			const uint64_t t2 = prev_t;
			int j = i - 1;
			do
			{
				indices[j + 1] = prev_t;
				--j;

				if (j < 0) {
					break;
				}

				prev_t = indices[j];
			} while (smaller(v, t, prev_t));
			indices[j + 1] = t;
			t = t2;
		}
		prev_t = t;
	}
}


inline void init128buckets(__m256i* buckets, uint64_t* indices) {
    __m256i to_write = _mm256_set1_epi64x((uintptr_t) indices);
	_mm256_store_si256(buckets, to_write=_mm256_add_epi64(to_write, bucket_0123));
	#define WRITE4 _mm256_store_si256(++buckets, to_write=_mm256_add_epi64(to_write, _4buckets));
	WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 // 32 buckets
	WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 // 64
	WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 // 96
	WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 WRITE4 // 128
	#undef WRITE4
}

void sort_indices1(uint8_t* v, uint64_t* indices, uint64_t* tmp_indices)
{
	uint8_t **buckets = (uint8_t**) (tmp_indices);
	uint64_t **buckets64 = (uint64_t**) (buckets);
	init128buckets((__m256i*) (buckets), indices);

	const uint64_t *const last = (uint64_t*) (v + (STAGE1_SIZE & -4));
	union { uint64_t *next; uint32_t *next32; };
	next = (uint64_t *) --v;
	// read bucket position and then advance it
	#define READ_AND_ADVANCE(X) uint64_t *p##X = buckets64[b##X]; buckets[b##X] += ITEM_SIZE;
    #define MOVB(src, dest) asm ("movb %0, %1" : /* No outputs */ : "r" (src), "r" (dest));
	uint64_t b07 = bswap_64(*next); ++next32;
	uint64_t b8b = bswap_64(*next);
	for (union {uint64_t tmp; uint8_t tmp8;}; next <= last; ++next32, b07=b8b, b8b=bswap_64(*next)) {
		uint8_t b4 = b07 >> 56, b2 = b07<<16 >> 56;
		READ_AND_ADVANCE(4) forceRegister(b2);
		READ_AND_ADVANCE(2)
		uint8_t b1 = b07<<8 >> 56;
		READ_AND_ADVANCE(1) uint8_t b3=b07<<24 >> 56; forceRegister(b3);
	    READ_AND_ADVANCE(3)
		                    tmp = b8b >> 8; MOVB(b3, tmp8)
		*p4 = tmp;          tmp = b07;
		*p2 = b07<<8 | b1;  MOVB((uint8_t)(b07>>56), tmp8)
		*p1 = tmp;          tmp = b8b >>16; MOVB(b2, tmp8)
		*p3 = tmp;
	}
	// constexpr int remainder = STAGE1_SIZE+1 & 3;
	// There are 2 remaining
	uint8_t b1 = b07<<8 >> 56;
	READ_AND_ADVANCE(1)
	*p1 = b07 >> 56;
	*v++ = b1;



	// uint64_t left8 = bswap_64(*next++), right8 = bswap_64(*next);
	// for (uint64_t tmp; next++ < last; left8 = tmp) {
	// 	// uint64_t b7 = left8 & 255, b8 = right8 >> 56;
	// 	// READ_AND_ADVANCE(7)
	// 	// READ_AND_ADVANCE(8)
	// 	// uint64_t b1 = left8<< 8 >> 56, b2 = left8<<16 >> 56;
	// 	// READ_AND_ADVANCE(1)
	// 	// READ_AND_ADVANCE(2)
	// 	// uint64_t b3 = left8<<24 >> 56, b4 = left8<<32 >> 56;
	// 	// READ_AND_ADVANCE(3)
	// 	// READ_AND_ADVANCE(4)
	// 	// uint64_t b5 = left8<<40 >> 56, b6 = left8<<48 >> 56;
	// 	// READ_AND_ADVANCE(5)
	// 	// READ_AND_ADVANCE(6)

	// 	// *p7 = right8>>24 <<8 | b6;
	// 	// *p8 = right8& -256 | b7; // the high 16 bits don't matter
	// 	// *p1 = left8& -256 | left8 >> 56;
	// 	// *p2 = left8<< 8 | b1;
	// 	// *p3 = left8<<16 | b8<<8 | b2;
	// 	// *p4 = left8<<24 | right8>>48 <<8 | b3;
	// 	// *p5 = left8<<32 | right8>>40 <<8 | b4;
	// 	// *p6 = left8<<40 | right8>>32 <<8 | b5;

	// 	uint64_t b7 = left8 & 255, b8 = right8 >> 56, b6 = left8<<48 >> 56;
	// 	READ_AND_ADVANCE(7)
	// 	READ_AND_ADVANCE(8)
	// 	uint64_t b4 = left8<<32 >> 56, b5 = left8<<40 >> 56;
	// 	READ_AND_ADVANCE(4)  *p7 = right8>>24 <<8 | b6;
	// 	READ_AND_ADVANCE(5)  *p8 = right8>>16 <<8 | b7; // the high 16 bits don't matter
	// 	uint64_t b3 = left8<<24 >> 56;
	// 	READ_AND_ADVANCE(6)  *p4 = left8<<24 | right8>>48 <<8 | b3;
	// 	READ_AND_ADVANCE(3)  *p5 = left8<<32 | right8>>40 <<8 | b4;
	// 	uint64_t b1 = left8<< 8 >> 56, b2 = left8<<16 >> 56;
	// 	READ_AND_ADVANCE(1)  *p6 = left8<<40 | right8>>32 <<8 | b5;
	// 	READ_AND_ADVANCE(2)  *p3 = left8<<16 | b2 | b8<<8;

    //     tmp = right8; right8 = bswap_64(*next);
	// 	*p1 = left8& -256 | left8 >> 56;
	// 	*p2 = left8<< 8 | b1;
	// }
	// // As (STAGE1_SIZE + 1) % 8 is 6, there r 6 more to go
	// // next is now equal to last, so the last 6 r in right8
	// // Note the last one will be sorted according to 0
	// uint64_t b1 = right8>>48 & 255, b2 = right8>>40 & 255;
	// READ_AND_ADVANCE(1)
	// READ_AND_ADVANCE(2)
	// uint64_t b3 = right8>>32 & 255, b4 = right8>>24 & 255;
	// READ_AND_ADVANCE(3)
	// READ_AND_ADVANCE(4)  *p1 = right8 | right8>>56;
	// uint64_t b5 = right8>>16 & 255;
	// READ_AND_ADVANCE(5)

    // *p2 = right8<<8 | b1;
	// *p3 = right8<<16 | b2;
    // *p4 = b5<<40 | b3;
	// *p5 = b4;

	// // uint64_t b4 = right8>>24 & 255, b5 = 0;
	// // READ_AND_ADVANCE(5)
	// // READ_AND_ADVANCE(4)
	// // uint64_t b1 = right8>>48 & 255, b2 = right8>>40 & 255;
	// // READ_AND_ADVANCE(1)
	// // READ_AND_ADVANCE(2)
	// // uint64_t b3 = right8>>32 & 255;
	// // READ_AND_ADVANCE(3)

	// // *p5 = b4;
	// // *p4 = b3;
	// // *p1 = right8 | right8>>56;
	// // *p2 = right8<<8 | b1;
	// // *p3 = right8<<16 | b2;
	#undef READ_AND_ADVANCE
}

void sort_indices2(uint32_t N, const uint8_t* v, uint64_t* indices, uint64_t* tmp_indices)
{
	alignas(16) uint32_t counters[1 << COUNTING_SORT_BITS] = {};
	alignas(16) uint32_t counters2[1 << COUNTING_SORT_BITS];

	{
#define ITER(X) { \
			++counters[k << 8 >> (64 - COUNTING_SORT_BITS)]; \
            ++counters[k << 16>> (64 - COUNTING_SORT_BITS)]; \
			++counters[k << 24>> (64 - COUNTING_SORT_BITS)]; \
			++counters[(uint32_t) k >> (32 - COUNTING_SORT_BITS)]; \
            ++counters[k << 40>> (64 - COUNTING_SORT_BITS)]; \
            ++counters[k >> (64 - COUNTING_SORT_BITS)]; \
		}

		uint32_t i = 0;
		const uint32_t n = N-5;
        uint64_t k = bswap_64(*reinterpret_cast<const uint64_t*>(v));
		for (; i < n; i += 6, k = bswap_64(*reinterpret_cast<const uint64_t*>(v + i))) {
			ITER(0); 
		}

        switch (N-i)
		{
		case 5: ++counters[(uint32_t) k >> (32 - COUNTING_SORT_BITS)];
		case 4: ++counters[k << 24 >> (64 - COUNTING_SORT_BITS)];
		case 3: ++counters[k << 16 >> (64 - COUNTING_SORT_BITS)];
		case 2: ++counters[k << 8 >> (64 - COUNTING_SORT_BITS)];
		case 1: ++counters[k >> (64 - COUNTING_SORT_BITS)];
		default:
			break;
		}
#undef ITER
	}

	uint32_t prev = static_cast<uint32_t>(-1);
	for (uint32_t i = 0; i < (1 << COUNTING_SORT_BITS); i += 8)
	{
#define ITER(X) { \
			uint32_t cur; prev += counters[i + X]; \
			counters[i + X] = forceRegister(cur = prev); \
		}
		ITER(0); ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7);
		//ITER(8); ITER(9); ITER(10); ITER(11); ITER(12); ITER(13); ITER(14); ITER(15);
#undef ITER
	}

	// std::copy(counters, counters+COUNTING_SORT_SIZE, counters2);

	std::copy(counters, counters+COUNTING_SORT_SIZE, counters2);

	// __builtin_memcpy_inline(counters2, counters, sizeof(uint32_t)*COUNTING_SORT_SIZE);

// 	{
// #define ITER(X) \
// 		do { \
// 			const uint64_t k = bswap_64(*reinterpret_cast<const uint64_t*>(v + (i - X))); \
// 			indices[counters[k >> (64 - COUNTING_SORT_BITS)]--] = (k & (static_cast<uint64_t>(-1) << 21)) | (i - X); \
// 		} while (0)

// 		uint32_t i = N;
// 		for (; i >= 8; i -= 8) {
// 			ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7); ITER(8);
// 		}
// 		for (; i > 0; --i) {
// 			ITER(1);
// 		}

// #undef ITER
// 	}

	{
#define ITER(X) \
		do { \
			const uint64_t k = bswap_64(*reinterpret_cast<const uint64_t*>(v+(i - X))); \
			indices[counters[k >> (64 - COUNTING_SORT_BITS)]--] = (k & (static_cast<uint64_t>(-1) << 21)) | (i - X); \
		} while (0)

		int64_t i = N-8;
        // const auto v8 = forceRegister(v+8);
		for (; forceRegister(i) >= 0; i -= 8) {
			ITER(-7); ITER(-6); ITER(-5); ITER(-4); ITER(-3); ITER(-2); ITER(-1); ITER(0);
		}
		for (i=N&7; forceRegister(i) > 0; --i) {
			ITER(1);
		}

#undef ITER
	}

	uint32_t prev_i = 0;
	for (uint32_t i0 = 0; i0 < (1 << COUNTING_SORT_BITS); ++i0) {
		const uint32_t i = counters2[i0] + 1;
		const uint32_t n = i - prev_i;
		if (n > 1) {
			memset(counters, 0, sizeof(uint32_t) * (1 << COUNTING_SORT_BITS));

			const uint32_t n8 = (n / 8) * 8;
			uint32_t j = 0;

#define ITER(X) { \
				const uint64_t k = indices[prev_i + j + X]; \
				++counters[(k >> (64 - COUNTING_SORT_BITS * 2)) & ((1 << COUNTING_SORT_BITS) - 1)]; \
				tmp_indices[j + X] = k; \
			}
			for (; j < n8; j += 8) {
				ITER(0); ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7);
			}
			for (; j < n; ++j) {
				ITER(0);
			}
#undef ITER

			uint32_t prev = static_cast<uint32_t>(-1);
			for (uint32_t j = 0; j < (1 << COUNTING_SORT_BITS); j += 8)
			{
#define ITER(X) { \
					uint32_t cur; prev += counters[j + X]; \
			        	counters[j + X] = (cur = prev); \
				}
				ITER(0); ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7);
				//ITER(8); ITER(9); ITER(10); ITER(11); ITER(12); ITER(13); ITER(14); ITER(15);
				//ITER(16); ITER(17); ITER(18); ITER(19); ITER(20); ITER(21); ITER(22); ITER(23);
				//ITER(24); ITER(25); ITER(26); ITER(27); ITER(28); ITER(29); ITER(30); ITER(31);
#undef ITER
			}

#define ITER(X) { \
				const uint64_t k = tmp_indices[j - X]; \
				const uint32_t index = counters[(k >> (64 - COUNTING_SORT_BITS * 2)) & ((1 << COUNTING_SORT_BITS) - 1)]--; \
				indices[prev_i + index] = k; \
			}
			for (j = n; j >= 8; j -= 8) {
				ITER(1); ITER(2); ITER(3); ITER(4); ITER(5); ITER(6); ITER(7); ITER(8);
			}
			for (; j > 0; --j) {
				ITER(1);
			}
#undef ITER

			uint64_t prev_t = indices[prev_i];
			for (uint64_t* p = indices + prev_i + 1, *e = indices + i; p != e; ++p)
			{
				uint64_t t = *p;
				if (smaller(v, t, prev_t))
				{
					const uint64_t t2 = prev_t;
					uint64_t* p1 = p;
					do
					{
						*p1 = prev_t;
						--p1;

						if (p1 <= indices + prev_i) {
							break;
						}

						prev_t = *(p1 - 1);
					} while (smaller(v, t, prev_t));
					*p1 = t;
					t = t2;
				}
				prev_t = t;
			}
		}
		prev_i = i;
	}
}

bool xmrig::astrobwt::astrobwt_dero(const void* input_data, uint32_t input_size, void* scratchpad, uint8_t* output_hash, int stage2_max_size, bool avx2)
{
	alignas(8) uint8_t key[32];
	uint8_t* scratchpad_ptr = (uint8_t*)(scratchpad) + 64;
	uint8_t* stage1_output = scratchpad_ptr;
	uint8_t* stage2_output = scratchpad_ptr;
	uint64_t* indices = (uint64_t*)(scratchpad_ptr + ALLOCATION_SIZE);
	uint64_t* tmp_indices = (uint64_t*)(scratchpad_ptr + ALLOCATION_SIZE * 9);
	uint8_t* stage1_result = (uint8_t*)(tmp_indices);
	uint8_t* stage2_result = (uint8_t*)(tmp_indices);

#ifdef ASTROBWT_AVX2
	if (hasAVX2 && avx2) {
		SHA3_256_AVX2_ASM(input_data, input_size, key);
		Salsa20_XORKeyStream_AVX256(key, stage1_output, STAGE1_SIZE);
	}
	else
#endif
	{
		sha3_HashBuffer(256, SHA3_FLAGS_NONE, input_data, input_size, key, sizeof(key));
		Salsa20_XORKeyStream(key, stage1_output, STAGE1_SIZE);
	}

	sort_indices(STAGE1_SIZE + 1, stage1_output, indices, tmp_indices);

	{
		const uint8_t* tmp = stage1_output - 1;
		for (int i = 0; i <= STAGE1_SIZE; ++i) {
			stage1_result[i] = tmp[indices[i] & ((1 << 21) - 1)];
		}
	}

#ifdef ASTROBWT_AVX2
	if (hasAVX2 && avx2)
		SHA3_256_AVX2_ASM(stage1_result, STAGE1_SIZE + 1, key);
	else
#endif
		sha3_HashBuffer(256, SHA3_FLAGS_NONE, stage1_result, STAGE1_SIZE + 1, key, sizeof(key));

	const int stage2_size = STAGE1_SIZE + (*(uint32_t*)(key) & 0xfffff);
	if (stage2_size > stage2_max_size) {
		return false;
	}

#ifdef ASTROBWT_AVX2
	if (hasAVX2 && avx2) {
		Salsa20_XORKeyStream_AVX256(key, stage2_output, stage2_size);
	}
	else
#endif
	{
		Salsa20_XORKeyStream(key, stage2_output, stage2_size);
	}

	sort_indices2(stage2_size + 1, stage2_output, indices, tmp_indices);

	{
		const uint8_t* tmp = stage2_output - 1;
		int i = 0;
		const int n = ((stage2_size + 1) / 4) * 4;

		for (; i < n; i += 4)
		{
			stage2_result[i + 0] = tmp[indices[i + 0] & ((1 << 21) - 1)];
			stage2_result[i + 1] = tmp[indices[i + 1] & ((1 << 21) - 1)];
			stage2_result[i + 2] = tmp[indices[i + 2] & ((1 << 21) - 1)];
			stage2_result[i + 3] = tmp[indices[i + 3] & ((1 << 21) - 1)];
		}

		for (; i <= stage2_size; ++i) {
			stage2_result[i] = tmp[indices[i] & ((1 << 21) - 1)];
		}
	}

#ifdef ASTROBWT_AVX2
	if (hasAVX2 && avx2)
		SHA3_256_AVX2_ASM(stage2_result, stage2_size + 1, output_hash);
	else
#endif
		sha3_HashBuffer(256, SHA3_FLAGS_NONE, stage2_result, stage2_size + 1, output_hash, 32);

	return true;
}


void xmrig::astrobwt::init()
{
	if (!astrobwtInitialized) {
#		ifdef ASTROBWT_AVX2
		hasAVX2 = Cpu::info()->hasAVX2();
#		endif

		astrobwtInitialized = true;
	}
}


template<>
void xmrig::astrobwt::single_hash<xmrig::Algorithm::ASTROBWT_DERO>(const uint8_t* input, size_t size, uint8_t* output, cryptonight_ctx** ctx, uint64_t)
{
	astrobwt_dero(input, static_cast<uint32_t>(size), ctx[0]->memory, output, std::numeric_limits<int>::max(), true);
}