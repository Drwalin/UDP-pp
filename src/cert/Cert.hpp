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

#ifndef DRWALIN_CERTIFICATE_HPP
#define DRWALIN_CERTIFICATE_HPP

#include <PK.hpp>
#include <SHA256.hpp>

#include <cstring>
#include <cinttypes>

class Certificate {
public:
	
	~Certificate();
	
	static SignCertificate
	
private:
	
	Certificate();
	
	uint8_t *buffer;
	size_t size;
};

#endif

