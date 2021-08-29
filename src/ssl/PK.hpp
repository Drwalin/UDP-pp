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

#ifndef PK_HPP
#define PK_HPP

#include <pk.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

int PKRandomGeneratorFunction(void* _gen, unsigned char* buf, size_t len);

class PKPublic {
public:

	inline static thread_local int err = 0;
	
	PKPublic();
	PKPublic(const void *key, int length);
	PKPublic(const char *keyFileName);
	~PKPublic();

	void Clear();
	
	bool Init(const void *key, int length);
	bool Init(const char *keyFileName);
	
	bool GetDER(void *buf, int *len);
	bool GetPEM(char *buf, int *len);
	
	bool WriteFilePEM(const char *fileName);
	bool WriteFileDER(const char *fileName);
	
public:
	
	bool Encrypt(const void *input,
			size_t inputLen,
			void *output,
			size_t *outputLen);
	bool VerifyHash(const void *hash,
			size_t hashLen,
			const void *signature,
			size_t signatureLen);

private:

	void Init();

	mbedtls_pk_context ctx;
	std::mt19937_64 mtgen;
};

class PKPrivate {
public:

	PKPrivate();
	PKPrivate(const void *key, int length, const char *password);
	PKPrivate(const char *keyFileName, const char *password);
	~PKPrivate();
	
	void Clear();
	
	bool Init(const void *key, int length, const char *password);
	bool Init(const char *keyFileName, const char *password);
	
	bool GetPublic(PKPublic& pubkey);
	
	bool GetDER(void *buf, int *len);
	bool GetPEM(char *buf, int *len);
	
	bool WriteFilePEM(const char *fileName);
	bool WriteFileDER(const char *fileName);
	
public:

	bool Decrypt(const void *input,
			size_t inputLen,
			void *output,
			size_t *outputLen);
	bool SignHash(const void *hash,
			size_t hashLen,
			void *signature,
			size_t *signatureLen);

private:

	void Init();

	mbedtls_pk_context ctx;
	std::mt19937_64 mtgen;
};

#endif

