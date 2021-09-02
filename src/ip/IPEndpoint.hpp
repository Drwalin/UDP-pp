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

#ifndef UDP_ENDPOINT_HPP
#define UDP_ENDPOINT_HPP

#include <cinttypes>

#include "IP.hpp"

namespace ip {
	struct Endpoint {
		Endpoint() {
			address = 0;
			port = 0;
			_padding = 0;
		}
		Endpoint(const Endpoint& other) {
			*(uint64_t*)this = *(uint64_t*)&other;
			_padding = 0;
		}
		Endpoint(Endpoint&& other) {
			*(uint64_t*)this = *(uint64_t*)&other;
			_padding = 0;
		}
		Endpoint(uint32_t ipv4, uint16_t port) {
			address = ipv4;
			this->port = port;
			_padding = 0;
		}
		Endpoint(const struct sockaddr_in& addr) {
			port = ntohs(addr.sin_port);
#ifdef OS_WINDOWS
			address = addr.sin_addr.S_un.S_addr;
#else
			address = addr.sin_addr.s_addr;
#endif
			_padding = 0;
		}
		
		Endpoint& operator=(const Endpoint other) {
			*(uint64_t*)this = (uint64_t)other;
			return *this;
		}
		Endpoint& operator=(const struct sockaddr_in& addr) {
			return *this = Endpoint(addr);
		}
		
		operator struct sockaddr_in() const {
			return GetSocketAddrress();
		}
		
		struct sockaddr_in GetSocketAddrress() const {
			struct sockaddr_in ret;
			ret.sin_family = AF_INET;
			ret.sin_port = htons(port);
			ret.sin_addr.s_addr = address;
			return ret;
		}
		
		
		
		inline operator uint64_t() const {
			return INT();
		}
		
		inline bool operator==(Endpoint other) const {
			return INT() == other.INT();
		}
		
		inline bool operator!=(Endpoint other) const {
			return INT() != other.INT();
		}
		
		inline bool operator<=(Endpoint other) const {
			return INT() <= other.INT();
		}
		
		inline bool operator>=(Endpoint other) const {
			return INT() >= other.INT();
		}
		
		inline bool operator<(Endpoint other) const {
			return INT() < other.INT();
		}
		
		inline bool operator>(Endpoint other) const {
			return INT() > other.INT();
		}
		
		
		inline uint64_t INT() const {
			return *(uint64_t*)this;
		}
		inline uint64_t& INT() {
			return *(uint64_t*)this;
		}
		
		uint32_t address;
		uint16_t port;
		uint16_t _padding;
	};
	
	// TODO: replace inet_addr() with gethostbyname()
	inline Endpoint GetAddress(const char* ipstr, uint16_t port) {
		return Endpoint(inet_addr(ipstr), port);
	}
}

#endif

