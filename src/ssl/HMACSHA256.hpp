/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2021 Marek Zalewski aka Drwalin
 *
 *  This is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef HMACSHA256_HPP
#define HMACSHA256_HPP

#include <sha256.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

class HMACSHA256 {
public:

	inline static thread_local int err = 0;

	inline const static uint64_t i_pad = 0x3636363636363636;
	inline const static uint64_t o_pad = 0x5c5c5c5c5c5c5c5c;

	HMACSHA256(const void *key) {
		Reset(key);
	}

	HMACSHA256(const void *key, void *hmac, const void *input, size_t bytes) {
		Reset(key);
		Update(input, bytes);
		Finish(hmac);
	}

	HMACSHA256(const void* key, void *hmac, size_t count, ...) {
		Reset(key);
		va_list vl;
		va_start(vl, count);
		for(size_t i=0; i<count; ++i) {
			const void *input = va_arg(vl, const void*);
			size_t bytes = va_arg(vl, size_t);
			Update(input, bytes);
		}
		va_end(vl);
		Finish(hmac);
	}

	~HMACSHA256() {
		memset(&ctx, 0, sizeof(ctx));
		memset(okeypad, 0, 256/8);
		memset(ikeypad, 0, 256/8);
	}

	
	inline bool Reset() {
		mbedtls_sha256_starts(&ctx, 0);
		if((err = mbedtls_sha256_update(&ctx, ikeypad, 256/8)))
			return false;
		return true;
	}

	inline bool Reset(const void *key) {
		const uint64_t *key64 = (const uint64_t*)key;
		uint64_t *ikeypad = (uint64_t*)this->ikeypad;
		ikeypad[0] = key64[0] ^ i_pad;
		ikeypad[1] = key64[1] ^ i_pad;
		ikeypad[2] = key64[2] ^ i_pad;
		ikeypad[3] = key64[3] ^ i_pad;
		uint64_t *okeypad = (uint64_t*)(this->okeypad);
		okeypad[0] = key64[0] ^ o_pad;
		okeypad[1] = key64[1] ^ o_pad;
		okeypad[2] = key64[2] ^ o_pad;
		okeypad[3] = key64[3] ^ o_pad;
		
		mbedtls_sha256_starts(&ctx, 0);
		if((err = mbedtls_sha256_update(&ctx, (const uint8_t*)ikeypad, 256/8)))
			return false;
		return true;
	}

	inline bool Update(const void *input, size_t bytes) {
		if((err = mbedtls_sha256_update(&ctx, (const uint8_t*)input, bytes)))
			return false;
		return true;
	}
	
	inline bool Finish(void *hmac) {
		mbedtls_sha256_finish(&ctx, (uint8_t*)hmac);
		mbedtls_sha256_starts(&ctx, 0);
		if((err = mbedtls_sha256_update(&ctx, (const uint8_t*)okeypad, 256/8)))
			return false;
		if((err = mbedtls_sha256_update(&ctx, (const uint8_t*)hmac, 256/8)))
			return false;
		if((err = mbedtls_sha256_finish(&ctx, (uint8_t*)hmac)))
			return false;
		return true;
	}

private:

	mbedtls_sha256_context ctx;
	uint8_t okeypad[256/8];
	uint8_t ikeypad[256/8];
};

#endif

