/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2021-2022 Marek Zalewski aka Drwalin
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
#include <string>

#include "IP.hpp"

namespace ip {
	struct Endpoint {
		Endpoint() {
			ipv4.sin_family = AF_INET;
			ipv4.sin_port = 0;
#ifdef OS_WINDOWS
			ipv4.sin_addr.S_un.S_addr = 0;
#else
			ipv4.sin_addr.s_addr = 0;
#endif
		}
		Endpoint(struct addrinfo& ai) {
			
		}
		Endpoint(const Endpoint& other) {
			*(uint64_t*)this = *(uint64_t*)&other;
		}
		Endpoint(Endpoint&& other) {
			*(uint64_t*)this = *(uint64_t*)&other;
		}
		Endpoint(uint32_t addrv4, uint16_t port) {
			ipv4.sin_family = AF_INET;
			ipv4.sin_port = htons(port);
#ifdef OS_WINDOWS
			ipv4.sin_addr.S_un.S_addr = addrv4;
#else
			ipv4.sin_addr.s_addr = addrv4;
#endif
		}
		Endpoint(const struct sockaddr_in& addr) {
			ipv4 = addr;
		}
		
		Endpoint& operator=(const Endpoint& other) = default;
		Endpoint& operator=(const struct sockaddr_in& addr) {
			return *this = Endpoint(addr);
		}
		
		operator struct sockaddr_in() const {
			return GetSocketAddrress();
		}
		
		struct sockaddr_in GetSocketAddrress() const {
			return ipv4;
		}
		
		std::string ToString() const {
			char str[64];
			ToString(str);
			return str;
		}
		
		void ToString(char* str) const {
			int e[4];
			uint32_t address = 
#ifdef OS_WINDOWS
			ipv4.sin_addr.S_un.S_addr;
#else
			ipv4.sin_addr.s_addr;
#endif
			e[0] = (address)&0xFF;
			e[1] = (address>>8)&0xFF;
			e[2] = (address>>16)&0xFF;
			e[3] = (address>>24)&0xFF;
			snprintf(str, 64, "%i.%i.%i.%i:%i", e[0], e[1], e[2], e[3],
					ipv4.sin_port);
		}
		
		int Port() const {
			return ipv4.sin_port;
		}
		
		
		/*
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
		*/
		
	private:
		
		union {
			struct sockaddr_in ipv4;
			struct sockaddr_in6 ipv6;
		};
	};
	
	// TODO: replace inet_addr() with gethostbyname()
	inline Endpoint GetAddress(const char* ipstr, uint16_t port) {
		return Endpoint(inet_addr(ipstr), port);
	}
	
	bool DnsResolve(const char* ipstr, uint16_t port, Endpoint* ips,
			int maxIps, int& ipsNum);
	Endpoint DnsResolve(const char* ipstr, uint16_t port);
}

#endif

