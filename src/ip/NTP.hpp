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

#ifndef NTP_HPP
#define NTP_HPP

#include <cinttypes>
#include <vector>

#include "IPEndpoint.hpp"

namespace ip {
	namespace udp {
		int32_t GetBigEndian(const uint8_t *buf, int32_t offset);
		// Network time protocol
		int64_t NTP(const std::vector<ip::Endpoint>& serverAddresses);
	}
}

#endif
