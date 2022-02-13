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
			errno = 0;
			blocking = true;
			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if(fd < 0)
				Error("Socket() error: %i", (int)fd);
		}
		
		Socket::Socket(uint16_t port) {
			errno = 0;
			blocking = true;
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
					Error("Socket() error: %i\n", (int)fd);
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
		
		bool Socket::SetNonblocking(bool value) {
			blocking = !value;
#ifdef OS_WINDOWS
				u_long mode = 1;
				ioctlsocket(fd, FIONBIO, &mode);
#else
				/*
				int flags = fcntl(fd, F_GETFL);
				if(flags < 0) {
					Error("fcntl cannot get flags of a socket");
					return false;
				}
				if(fcntl(fd, F_SETFL,
							value
							? (flags|O_NONBLOCK)
							: (flags&(~O_NONBLOCK))
						) < 0) {
					Error("fcntl cannot set nonblocking socket");
					return false;
				}
				*/
#endif
				return true;
		}
		
		bool Socket::SetSendBufferSize(int value) {
			// TODO: Test on windows
#ifdef OS_WINDOWS
			return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&value,
					sizeof(value)) == 0;
#else
			return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value,
					sizeof(value)) == 0;
#endif
		}
		
		bool Socket::SetRecvBufferSize(int value) {
			// TODO: Test on windows
#ifdef OS_WINDOWS
			return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&value,
					sizeof(value)) == 0;
#else
			return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value,
					sizeof(value)) == 0;
#endif
		}
		
		bool Socket::Receive(Packet& packet, Endpoint& endpoint) {
			errno = 0;
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
#ifdef OS_WINDOWS
						0,
#else
						blocking ? 0 : MSG_DONTWAIT,
#endif
						sa,
						&slen);
			if(packet.size == SOCKET_ERROR) {
#ifdef OS_WINDOWS
				int err = WSAGetLastError();
				if(err == EAGAIN || err == EWOULDBLOCK || err == WSAEWOULDBLOCK) {
					return false;
				}
				Error("recvfrom packet.size=%i, error = %i", packet.size, err);
#else
				if(errno == EAGAIN || errno == EWOULDBLOCK) {
					return false;
				}
				Error("recvfrom packet.size=%i, errno = %i", packet.size, errno);
#endif
				packet.size = 0;
				return false;
			}
			endpoint = end;
			return true;
		}
		
		bool Socket::Send(const Packet& packet, Endpoint endpoint) {
			errno = 0;
			struct sockaddr_in end = endpoint;
			struct sockaddr *sa = (struct sockaddr*)&end;
			if(sendto(fd,
						(char*)packet.buffer,
						packet.size,
#ifdef OS_WINDOWS
						0,
#else
						blocking ? 0 : MSG_DONTWAIT,
#endif
						sa,
						sizeof(end)) == SOCKET_ERROR) {
#ifdef OS_WINDOWS
				if(err == EAGAIN || err == EWOULDBLOCK || err == WSAEWOULDBLOCK) {
					return false;
				}
#else
				if(errno == EAGAIN || errno == EWOULDBLOCK) {
					return false;
				}
#endif
				Error("sendto");
				return false;
			}
			return true;
		}
	}
}

