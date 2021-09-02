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

#include "UDPSocket.hpp"

#include <cerrno>

namespace ip {
	namespace udp {
		Socket::Socket() {
			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(fd < 0)
				printf("Socket() error: %i", (int)fd);
		}
		
		Socket::Socket(uint16_t port) {
			struct sockaddr_in end = Endpoint(0, port).GetSocketAddrress();
			struct sockaddr *sa = (struct sockaddr*)&end;
#ifdef OS_WINDOWS
			end.sin_addr.s_addr = INADDR_ANY;
			fd = socket(AF_INET, SOCK_DGRAM, 0);
#else
			end.sin_addr.s_addr = htonl(INADDR_ANY);
			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
			if(fd != INVALID_SOCKET) {
				if(bind(fd, sa, sizeof(end)) == SOCKET_ERROR) {
					printf("Socket() error: %i\n", (int)fd);
					closesocket(fd);
					fd = INVALID_SOCKET;
				}
			} else
				Error("Socket() error: %i\n", (int)fd);
		}
		
		Socket::~Socket() {
			if(fd != INVALID_SOCKET)
				closesocket(fd);
			fd = INVALID_SOCKET;
		}
		
		bool Socket::Receive(Packet& packet, Endpoint& endpoint) {
			struct sockaddr_in end;
			struct sockaddr *sa = (struct sockaddr*)&end;
#ifdef OS_WINDOWS
			int slen = sizeof(end);
#else
			unsigned slen = sizeof(end);
#endif
			packet.size = recvfrom(fd,
						(char*)packet.buffer,
						ip::Packet::MAX_SIZE,
						0,
						sa,
						&slen);
			if(packet.size == SOCKET_ERROR) {
				Error("recvfrom");
				packet.size = 0;
				return false;
			}
			printf("\n\n Received:\n   ");
			for(int i=0; i<packet.size; ++i)
				printf(" %2.2X", packet.buffer[i]);
			printf("\n\n");
			endpoint = end;
			return true;
		}
		
		bool Socket::Send(const Packet& packet, Endpoint endpoint) {
			printf("\n\n Sending:\n   ");
			for(int i=0; i<packet.size; ++i)
				printf(" %2.2X", packet.buffer[i]);
			printf("\n\n");
			struct sockaddr_in end = endpoint;
			struct sockaddr *sa = (struct sockaddr*)&end;
			if(sendto(fd,
						(char*)packet.buffer,
						packet.size,
						0,
						sa,
						sizeof(end)) == SOCKET_ERROR) {
				Error("sendto");
				return false;
			}
			return true;
		}
	}
}

