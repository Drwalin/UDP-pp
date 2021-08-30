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

#ifndef MBEDTLS_UTIL_HPP
#define MBEDTLS_UTIL_HPP

#include <cstdio>

#include <mutex>

#include <error.h>

#define MBEDTLS_ERROR() { \
	char ___STR[10000]; \
	mbedtls_strerror(mbedtls::err, ___STR, 10000); \
	mbedtls::err = 0; \
	std::lock_guard<std::mutex> lock(mbedtls::mutex); \
	printf("\n   mbedtls error(" __FILE__ ":%i): %s\n ", \
			__LINE__, ___STR); \
	fflush(stdout); \
}

#define MBEDTLS_ERROR_PRINTF(MESSAGE, ...) { \
	char ___STR[10000]; \
	mbedtls_strerror(mbedtls::err, ___STR, 10000); \
	mbedtls::err = 0; \
	std::lock_guard<std::mutex> lock(mbedtls::mutex); \
	printf("\n   mbedtls error(" __FILE__ ":%i): %s\n " MESSAGE, \
			__LINE__, ___STR, __VA_ARGS__); \
	fflush(stdout); \
}

namespace mbedtls {
	
	extern thread_local int err;
	extern std::mutex mutex;
	
	inline const static int MAX_BYTES = 16000;
	
	int RandomInt(void *_gen, uint8_t *buf, size_t len);
	int Random(void *_gen, uint8_t *buf, size_t len);
	int Random(void *_gen, void *buf, size_t len);
	template<typename T>
	int Random(void *_gen, T *buf, size_t len) {
		return RandomInt(_gen, (uint8_t*)buf, len);
	}
}

#endif

