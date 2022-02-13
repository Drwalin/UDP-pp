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

/*
   Based on:
   https://www.binarytides.com/programming-udp-sockets-c-linux/
   https://www.binarytides.com/udp-socket-programming-in-winsock/
*/

#include "IP.hpp"

#include <cstring>

namespace ip {
	
#ifndef IP_NO_MUTEX
	std::mutex mutex;
#endif
	
#ifdef OS_WINDOWS
	
	int _Error_(int line, const char* file) {
		DWORD errorMessageID = WSAGetLastError();//GetLastError();
		if(errorMessageID == 0)
			return 0;

		LPSTR messageBuffer = NULL;

		size_t size =
			FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					errorMessageID,
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPSTR)&messageBuffer,
					0,
					NULL);
		fprintf(stderr, "(WSA)Error(%s:%i): ", file, line);
		fwrite(messageBuffer, size, 1, stderr);
		fprintf(stderr, "\n");
		fflush(stderr);

		LocalFree(messageBuffer);
		return errorMessageID;
	}

	WSADATA wsa;
	
	bool Init() {
		if(WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
			return false;
		}
		return true;
	}
	
	void Deinit() {
		WSACleanup();
	}
#else
	int _Error_(int line, const char* file) {
		fprintf(stderr, "(Linux)Error(%s:%i) (%i): %s\n", file, line, errno,
				std::strerror(errno));
		return errno;
	}
	bool Init() {
		return true;
	}
	void Deinit() {
	}
#endif
}

