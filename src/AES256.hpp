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

#ifndef AES256_HPP
#define AES256_HPP

#include <aes.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

class AES256 {
public:

	inline static thread_local int err = 0;

	AES256(const void *key) {
		Reset(key);
	}

	~AES256() {
		memset(&enc, 0, sizeof(enc));
		memset(&dec, 0, sizeof(dec));
	}


	static inline void GenerateIV(void *iv) {
		uint16_t *ivs = (uint16_t*)iv;
		ivs[0] = rand();
		ivs[1] = rand();
		ivs[2] = rand();
		ivs[3] = rand();
		ivs[4] = rand();
		ivs[5] = rand();
		ivs[6] = rand();
		ivs[7] = rand();
	}
	
	inline void Reset(const void *key) {
		mbedtls_aes_init(&enc);
		mbedtls_aes_setkey_enc(&enc, (const uint8_t*)key, 256);

		mbedtls_aes_init(&dec);
		mbedtls_aes_setkey_dec(&dec, (const uint8_t*)key, 256);
	}

	inline void Encrypt(const void *iv,
			const void *input,
			void *output,
			size_t bytes) {
		uint8_t temp[16];
		memcpy(temp, iv, 16);
		err = mbedtls_aes_crypt_cbc(&enc,
				MBEDTLS_AES_ENCRYPT,
				bytes,
				temp,
				(const uint8_t*)input,
				(uint8_t*)output);
	}

	inline void Decrypt(const void *iv,
			const void *input,
			void *output,
			size_t bytes) {
		uint8_t temp[16];
		memcpy(temp, iv, 16);
		err = mbedtls_aes_crypt_cbc(&dec,
				MBEDTLS_AES_DECRYPT,
				bytes,
				temp,
				(const uint8_t*)input,
				(uint8_t*)output);
	}

private:

	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
};

#endif

