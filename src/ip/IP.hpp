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

#ifndef IP_HPP
#define IP_HPP

#include "OSCheck.hpp"

#ifndef IP_NO_MUTEX
#include <mutex>
#endif

#ifdef OS_WINDOWS
#include <winsock2.h>
#endif

#ifdef OS_LINUX
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef OS_LINUX
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#define closesocket(FD) close(FD)
#define SOCKET int
#endif

namespace ip {
#ifndef IP_NO_MUTEX
	extern std::mutex mutex;
#endif
	int _Error_(int line);
	bool Init();
	void Deinit();
}

#ifndef IP_NO_MUTEX
#define Error(...) { \
	fprintf(stderr,"Error: "); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, ":  "); \
	fflush(stderr); \
	ip::_Error_(__LINE__); \
}
#define ErrorRet(...) { \
	fprintf(stderr,"Error: "); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, ":  "); \
	fflush(stderr); \
	auto ret = ip::_Error_(__LINE__); \
	WSACleanup(); \
	return ret; \
}
#else
#define Error(...) { \
	std::lock_guard<std::mutex> lock(ip::mutex); \
	fprintf(stderr,"Error: "); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, ":  "); \
	fflush(stderr); \
	ip::_Error_(__LINE__); \
}
#define ErrorRet(...) { \
	std::lock_guard<std::mutex> lock(ip::mutex); \
	fprintf(stderr,"Error: "); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, ":  "); \
	fflush(stderr); \
	auto ret = ip::_Error_(__LINE__); \
	WSACleanup(); \
	return ret; \
}
#endif
	

#endif
