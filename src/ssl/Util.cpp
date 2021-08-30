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

#include <random>
#include <error.h>

#include "Util.hpp"

namespace mbedtls {
	
	thread_local int err = 0;
	std::mutex mutex;
	
	static thread_local std::mt19937_64 _staticGen;
	
	int RandomInt(void *_gen, uint8_t *buf, size_t len) {
		std::mt19937_64 &gen = (_gen!=NULL) ? *(std::mt19937_64*)_gen : _staticGen;
		for(; len>=8; len-=8, buf+=8)
			*(uint64_t*)buf = gen();
		for(; len; --len, ++buf)
			*buf = gen();
		return 0;
	}
	
	int Random(void *_gen, uint8_t *buf, size_t len) {
		return RandomInt(_gen, buf, len);
	}
	
	int Random(void *_gen, void *buf, size_t len) {
		return RandomInt(_gen, (uint8_t*)buf, len);
	}
}

