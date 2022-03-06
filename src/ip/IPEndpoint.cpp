/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2022 Marek Zalewski aka Drwalin
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

#include "IPEndpoint.hpp"
#include <cstring>

#ifdef OS_WINDOWS

#else
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

namespace ip {
	
	/*
	bool DnsResolve(const char* ipstr, const char* protocolOrPort, Endpoint* ips,
			int maxIps, int& ipsNum) {
		struct addrinfo hint;
		struct addrinfo *ret;
		memset(&hint, 0, sizeof(hint));
		hint.ai_family = AF_INET;
		const int err = getaddrinfo(ipstr, protocolOrPort, &hint, &ret);
		if(err || ret==NULL)
			return false;
		ipsNum = 0;
		struct addrinfo *ip = ret;
		for(; ipsNum<maxIps && ip; ++ipsNum, ip=ip->ai_next) {
			ips[ipsNum] = Endpoint();
		}
		freeaddrinfo(ret);
		return true;
	}
	*/
	
	bool DnsResolve(const char* ipstr, uint16_t port, Endpoint* ips,
			int maxIps, int& ipsNum) {
		struct hostent* hosts = gethostbyname(ipstr);
		if(hosts == NULL) {
			Error("DNS resolve failed");
			return false;
		}
		ipsNum = 0;
		for(int i=0; hosts->h_addr_list[i] && ipsNum<maxIps; ++i) {
			uint32_t ip_n =
					((uint32_t)(uint8_t)(hosts->h_addr_list[i][0]))
					| (((uint32_t)(uint8_t)(hosts->h_addr_list[i][1]))<<8)
					| (((uint32_t)(uint8_t)(hosts->h_addr_list[i][2]))<<16)
					| (((uint32_t)(uint8_t)(hosts->h_addr_list[i][3]))<<24);
			ips[ipsNum] = Endpoint(ip_n, port);
			ipsNum++;
		}
		printf(" dns resolved: %i for %s\n", ipsNum, ipstr);
		return ipsNum != 0;
	}
	
	Endpoint DnsResolve(const char* ipstr, uint16_t port) {
		Endpoint endpoint;
		int num;
		DnsResolve(ipstr, port, &endpoint, 1, num);
		return endpoint;
	}
}

