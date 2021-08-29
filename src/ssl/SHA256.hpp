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

#ifndef SHA256_HPP
#define SHA256_HPP

#include "Util.hpp"

#include <sha256.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

class SHA256 {
public:

	SHA256() {
		Reset();
	}

	SHA256(void *hash, const void *input, size_t bytes) {
		Reset();
		Update(input, bytes);
		Finish(hash);
	}

	SHA256(void *hash, size_t count, ...) {
		Reset();
		va_list vl;
		va_start(vl, count);
		for(size_t i=0; i<count; ++i) {
			const void *input = va_arg(vl, const void*);
			size_t bytes = va_arg(vl, size_t);
			Update(input, bytes);
		}
		va_end(vl);
		Finish(hash);
	}

	~SHA256() {
		memset(&ctx, 0, sizeof(ctx));
	}


	inline void Reset() {
		mbedtls_sha256_starts(&ctx, 0);
	}

	inline bool Update(const void *input, size_t bytes) {
		if((mbedtls::err = mbedtls_sha256_update(&ctx, (const uint8_t*)input, bytes)))
			return false;
		return true;
	}

	inline bool Finish(void *hash) {
		if((mbedtls::err = mbedtls_sha256_finish(&ctx, (uint8_t*)hash)))
			return false;
		return true;
	}

private:

	mbedtls_sha256_context ctx;
};

#endif

