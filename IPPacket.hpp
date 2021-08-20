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

#ifndef IP_PACKET_HPP
#define IP_PACKET_HPP

#include <cinttypes>
#include <cstdio>
#include <cstdarg>
#include <cstring>

namespace IP {
	class Packet {
	public:
		Packet() {
			Clear();
		}
		
		inline const static uint32_t MAX_SIZE = 1456;
		
		inline void ResetReading() {
			read = 0;
		}
		
		inline void Clear() {
			size = 0;
			read = 0;
			memset(buffer, 0, MAX_SIZE);
		}
		
		
		template<typename T>
		inline bool Write(T value) {
			if(size+sizeof(T) <= MAX_SIZE) {
				*(T*)&(buffer[size]) = value;
				size += sizeof(T);
				return true;
			}
			return false;
		}
		
		inline bool Write(const void *data, uint16_t bytes) {
			if(size+bytes <= MAX_SIZE) {
				memmove(buffer+size, data, bytes);
				size += bytes;
				return true;
			}
			return false;
		}
		
		inline bool Write(const char* str) {
			for(char * const ptr = str;; ++ptr, ++size) {
				if(size < MAX_SIZE)
					buffer[size] = *ptr;
				if(!*ptr) {
					++size;
					break;
				}
			}
			return size<=MAX_SIZE;
		}
		
		
		template<typename T>
		inline bool Read(T& value) {
			if(read+sizeof(T) <= size) {
				value = *(T*)&(buffer[read]);
				read += sizeof(T);
				return true;
			}
			return false;
		}
		
		inline bool Read(void *data, uint16_t bytes) {
			if(read+bytes <= size) {
				voidmemmove(data, buffer+read, bytes);
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
		}
		
		
		inline bool Valid() const {
			return size<=MAX_SIZE && read<=size;
		}
		
		void* Buffer() {
			return buffer;
		}
		
		const void* Buffer() const {
			return buffer;
		}
		
		const uint32_t Size() const {
			return size;
		}
		
	private:
		
		uint8_t buffer[MAX_SIZE];
		uint32_t size;
		uint32_t read;
	};
}

#endif

