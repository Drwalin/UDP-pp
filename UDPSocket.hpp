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

/*
   Based on:
   https://www.binarytides.com/programming-udp-sockets-c-linux/
   https://www.binarytides.com/udp-socket-programming-in-winsock/
*/

#ifndef UDP_SOCKET_HPP
#define UDP_SOCKET_HPP

#include "OSCheck.hpp"

#include <cinttypes>

#include "IPEndpoint.hpp"
#include "IPPacket.hpp"
#include "IP.hpp"

namespace IP {
	namespace UDP {
		class Socket {
		public:
			
			Socket();
			Socket(uint16_t port);
			~Socket();
			
			inline bool Valid() const {return fd != INVALID_SOCKET;}
			
			bool Receive(Packet& packet, Endpoint& endpoint);
			bool Send(const Packet& packet, const Endpoint endpoint);
			
		private:
			
			int fd;
		};
	}
}

#endif

