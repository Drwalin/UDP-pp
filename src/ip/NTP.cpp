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

#include <cinttypes>
#include <vector>

#include "IPEndpoint.hpp"
#include "IPPacket.hpp"
#include "UDPSocket.hpp"

#include "NTP.hpp"

namespace ip {
	namespace udp {
		int32_t GetBigEndian(const uint8_t *buf, int32_t offset) {
			uint32_t time = 0;
			time |= buf[offset++]<<24;
			time |= buf[offset++]<<16;
			time |= buf[offset++]<<8;
			time |= buf[offset++];
			return time;
		}

		int64_t NTP(const std::vector<ip::Endpoint>& serverAddresses) {
			ip::udp::Socket socket;
			socket.SetTimeout(5000);
			ip::Packet packet;

			packet.WriteNull(48);
			packet.Buffer()[0] = 010;
			
			int count = 0;
			for(const ip::Endpoint& endpoint : serverAddresses) {
				if(socket.Send(packet, endpoint) == true)
					++count;
			}
			printf("sent: %i\n", count);
			if(count == 0)
				return -1;
			
			
			ip::Endpoint endpoint;
			if(socket.Receive(packet, endpoint) == true)
				return GetBigEndian(packet.Buffer(), 0)-2208988800U;
			return -2;
		}
	}
}

