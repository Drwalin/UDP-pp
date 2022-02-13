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

#ifndef IP_PACKET_HPP
#define IP_PACKET_HPP

#include <cinttypes>
#include <cstdio>
#include <cstdarg>
#include <cstring>

namespace ip {
	namespace udp {
		class Socket;
	}
	struct Packet {
		
		inline const static uint32_t MAX_SIZE = 1456;
		
		Packet() { Clear(); }
		inline void ResetReading() { read = 0; }
		inline void Clear() { size = 0; read = 0; }
		
		
		inline bool WriteNull(size_t count) {
			if(size+count > MAX_SIZE)
				return false;
			memset(buffer+size, 0, count);
			return true;
		}
		template<typename T>
		inline bool Write(T value) {
			return Write(&value, sizeof(T));
		}
		inline bool Write(const void *data, uint16_t bytes) {
			if((int64_t)size+bytes <= (int64_t)MAX_SIZE) {
				memmove(buffer+size, data, bytes);
				size += bytes;
				return true;
			}
			return false;
		}
		inline bool Write(const char* str) {
			for(char const * ptr = str;; ++ptr, ++size) {
				if((int64_t)size < (int64_t)MAX_SIZE)
					buffer[size] = *ptr;
				if(!*ptr) {
					++size;
					break;
				}
			}
			return (uint32_t)size<=MAX_SIZE;
		}
		
		
		template<typename T>
		inline T Read() {
			T ret=0;
			Read(ret);
			return ret;
		}
		template<typename T>
		inline T Read(bool& error) {
			T ret=0;
			error = Read(ret);
			return ret;
		}
		template<typename T>
		inline bool Read(T& value) {
			return Read(&value, sizeof(T));
		}
		inline bool Read(void *data, uint16_t bytes) {
			if((int64_t)read+bytes <= (int64_t)size) {
				memmove(data, buffer+read, bytes);
				read += bytes;
				return true;
			}
			return false;
		}
		inline bool Read(char *str) {
			for(char *dst=str; read!=size; ++dst, ++read) {
				if(read!=size) {
					*dst = buffer[read];
					if(!*dst) {
						++read;
						return true;
					}
				} else {
					*dst = 0;
					++read;
					return false;
				}
			}
			return false;
		}
		
		
		inline bool Valid() const {
			return size<=(int32_t)MAX_SIZE && read<=size;
		}
		
		inline uint8_t* Buffer() { return buffer; }
		inline const uint8_t* Buffer() const { return buffer; }
		inline const uint32_t Size() const { return size; }
		inline int32_t& Size() { return size; }
		
		
		uint8_t buffer[MAX_SIZE];
		int32_t size;
		int32_t read;
	};
}

#endif

