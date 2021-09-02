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

#ifndef READER_WRITER_HPP
#define READER_WRITER_HPP

#include <cinttypes>
#include <cstdio>
#include <cstdarg>
#include <cstring>

#include <vector>

namespace IP {
	class ReaderWriter {
	public:
		
		inline const static uint32_t MAX_SIZE = 1456-64;
		
		ReaderWriter() { Clear(); buffer.reserve(1500); }
		inline void ResetReading() { read = 0; }
		inline void Clear() { buffer.resize(0); read = 0; }
		
		
		template<typename T>
		inline bool WriteShortInt(T value) {
			// TODO:	Correct reading - currently
			// 			invalid byte order while reading
			while(value>0x7F) {
				uint8_t v = 0x80 | (value&0x7F);
				value >>= 7;
				buffer.emplace_back(v);
			}
			buffer.emplace_back(value&0x7F);
			return true;
		}
		template<typename T>
		inline bool WriteInt(T value) {
			// TODO:	Correct reading - currently
			// 			invalid byte order while reading
			size_t s = buffer.size();
			buffer.resize(buffer.size()+sizeof(T));
			uint8_t* ptr = &(buffer[s]);
			for(int i=0; i<sizeof(T); ++i)
				ptr[i] = (value>>(i*8))&0xFF;
			return true;
		}
		inline bool Write(const void *data, uint16_t bytes) {
			buffer.insert(buffer.end(), (uint8_t*)data, (uint8_t*)data+bytes);
			return true;
		}
		inline bool Write(const char* str) {
			size_t len = strlen(str);
			return Write(str, len+1);
		}
		
		
		template<typename T>
		inline bool ReadShortInt(T& value) {
			// TODO:	Correct reading - currently
			// 			invalid byte order while reading
			value = 0;
			while(true) {
				if(read == buffer.size())
					return false;
				value <<= 7;
				uint8_t v = buffer[read];
				if(value > 127) {
					value |= v&0x7F;
				} else {
					value |= v;
					return true;
				}
				++read;
			}
			return false;
		}
		template<typename T>
		inline T ReadInt() {
			T ret=0;
			ReadInt(ret);
			return ret;
		}
		template<typename T>
		inline T ReadInt(bool& error) {
			T ret=0;
			error = ReadInt(ret);
			return ret;
		}
		template<typename T>
		inline bool ReadInt(T& value) {
			// TODO:	Correct reading - currently
			// 			invalid byte order while reading
			value = 0;
			if(read + sizeof(T) > buffer.size())
				return false;
			uint8_t *b = &(buffer[read]);
			for(size_t i=0; i<sizeof(T); ++i) {
				value <<= 8;
				value |= b[i];
			}
			return true;
		}
		inline bool Read(void *data, uint16_t bytes) {
			if(read+bytes <= buffer.size()) {
				memmove(data, &(buffer[read]), bytes);
				read += bytes;
				return true;
			}
			return false;
		}
		inline bool Read(char *str) {
			for(char *dst=str; read!=buffer.size(); ++dst, ++read) {
				if(read!=buffer.size()) {
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
		
		
		inline bool Valid() const { return read<=buffer.size(); }
		
		inline uint8_t* Buffer() { return buffer.data(); }
		inline const uint8_t* Buffer() const { return buffer.data(); }
		inline const uint64_t Size() const { return buffer.size(); }
		inline void Resize(size_t size) { buffer.resize(size); }
		
		
		
		std::vector<uint8_t> buffer;
		size_t read;
	};
}

#endif



































































































