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

#include <random>
#include <error.h>

#include "Util.hpp"

namespace mbedtls {
	
	thread_local int err = 0;
	
	static thread_local std::mt19937_64 _staticGen;
	
	int Random(void* _gen, unsigned char* buf, size_t len) {
		std::mt19937_64 &gen = (_gen!=NULL) ? *(std::mt19937_64*)_gen : _staticGen;
		for(unsigned char *end=buf+len; buf!=end; ++buf) {
			*buf = gen();
		}
		return 0;
	}
}

#endif

