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

#ifndef RSA_HPP
#define RSA_HPP

#include <pk.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

int RSARandomGeneratorFunction(void* _gen, unsigned char* buf, size_t len) {
	std::mt19937 &gen = *(std::mt19937*)_gen;
	for(unsigned char *end=buf+len; buf!=end; ++buf) {
		*buf = gen();
	}
	return 0;
}

#define ERROR(ERR) { \
	char ___STR[10000]; \
	mbedtls_strerror(ERR, ___STR, 10000); \
	printf("\n   error(%i): %s", __LINE__, ___STR); \
	fflush(stdout); \
}

class RSAPublic {
public:

	inline static thread_local int err = 0;
	
	inline const static int MAX_BYTES = 16000;
	
	RSAPublic() {
		Init();
	}
	
	RSAPublic(const void *key, int length) {
		Init();
		Init(key, length);
	}

	RSAPublic(const char *keyFileName) {
		Init();
		Init(keyFileName);
	}

	~RSAPublic() {
		Clear();
	}


	inline void Clear() {
		mbedtls_pk_free(&ctx);
	}
	
	inline bool Init(const void *key, int length) {
		Clear();
		Init();
		if((err = mbedtls_pk_parse_public_key(&ctx,
						(const uint8_t*)key, length)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool Init(const char *keyFileName) {
		Clear();
		Init();
		if((err = mbedtls_pk_parse_public_keyfile(&ctx, keyFileName)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool GetDER(void *buf, int *len) {
		int orgLen = *len;
		err = *len = mbedtls_pk_write_pubkey_der(&ctx, (uint8_t*)buf, *len);
		if(*len < 0)
			return false;
		if(orgLen != *len)
			memmove(buf, (uint8_t*)buf+orgLen-*len, *len);
		return true;
	}
	
	inline bool GetPEM(char *buf, int *len) {
		err = mbedtls_pk_write_pubkey_pem(&ctx, (uint8_t*)buf, *len);
		if(err < 0)
			return false;
		*len = strlen(buf)+1;
		return true;
	}
	
	inline bool WriteFilePEM(const char *fileName) {
		char buf[MAX_BYTES];
		int len = MAX_BYTES;
		if(GetPEM(buf, &len) == false)
			return false;
		FILE *file = fopen(fileName, "wb");
		if(!file)
			return false;
		if(fwrite(buf, len, 1, file) != (size_t)len) {
			fclose(file);
			return false;
		}
		fclose(file);
		return true;
	}
	
	inline bool WriteFileDER(const char *fileName) {
		char buf[MAX_BYTES];
		int len = MAX_BYTES;
		if(GetDER(buf, &len) == false)
			return false;
		FILE *file = fopen(fileName, "wb");
		if(!file)
			return false;
		if(fwrite(buf, len, 1, file) != (size_t)len) {
			fclose(file);
			return false;
		}
		fclose(file);
		return true;
	}
	
public:
	
	inline bool Encrypt(const void *input,
			size_t inputLen,
			void *output,
			size_t *outputLen) {
		if((err = mbedtls_pk_encrypt(&ctx,
					(const uint8_t*)input,
					inputLen,
					(uint8_t*)output,
					outputLen,
					*outputLen,
					RSARandomGeneratorFunction,
					&mtgen)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool VerifyHash(const void *hash,
			size_t hashLen,
			const void *signature,
			size_t signatureLen) {
		if((err = mbedtls_pk_verify(&ctx,
					MBEDTLS_MD_SHA512,
					(const uint8_t*)hash,
					hashLen,
					(uint8_t*)signature,
					signatureLen)) < 0) {
			return false;
		}
		return true;
	}

private:

	inline void Init() {
		mbedtls_pk_init(&ctx);
	}

	mbedtls_pk_context ctx;
	std::mt19937_64 mtgen;
};

class RSAPrivate {
public:

	inline static thread_local int err = 0;
	
	inline const static int MAX_BYTES = 16000;
	
	RSAPrivate() {
		Init();
	}

	RSAPrivate(const void *key, int length, const char *password) {
		Init();
		Init(key, length, password);
	}

	RSAPrivate(const char *keyFileName, const char *password) {
		Init();
		Init(keyFileName, password);
	}

	~RSAPrivate() {
		Clear();
	}


	inline void Clear() {
		mbedtls_pk_free(&ctx);
	}
	
	inline bool Init(const void *key, int length, const char *password) {
		Clear();
		if((err = mbedtls_pk_parse_key(&ctx,
					(const uint8_t*)key,
					length,
					(const uint8_t*)password,
					password ? strlen(password) : 0,
					RSARandomGeneratorFunction,
					&mtgen)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool Init(const char *keyFileName, const char *password) {
		Clear();
		Init();
		if((err = mbedtls_pk_parse_keyfile(&ctx,
					keyFileName,
					password,
					RSARandomGeneratorFunction,
					&mtgen)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool GetPublic(RSAPublic& pubkey) {
		char buf[MAX_BYTES];
		int len = MAX_BYTES;
		err = len = mbedtls_pk_write_pubkey_der(&ctx, (uint8_t*)buf, len);
		if(err < 0)
			return false;
		return pubkey.Init(buf+MAX_BYTES-len, len);
	}
	
	inline bool GetDER(void *buf, int *len) {
		int orgLen = *len;
		err = *len = mbedtls_pk_write_key_der(&ctx, (uint8_t*)buf, *len);
		if(*len < 0)
			return false;
		if(orgLen != *len)
			memmove(buf, (uint8_t*)buf+orgLen-*len, *len);
		return true;
	}
	
	inline bool GetPEM(char *buf, int *len) {
		err = mbedtls_pk_write_key_pem(&ctx, (uint8_t*)buf, *len);
		if(err < 0)
			return false;
		*len = strlen(buf)+1;
		return true;
	}
	
	inline bool WriteFilePEM(const char *fileName) {
		char buf[MAX_BYTES];
		int len = MAX_BYTES;
		if(GetPEM(buf, &len) == false)
			return false;
		FILE *file = fopen(fileName, "wb");
		if(!file)
			return false;
		if(fwrite(buf, len, 1, file) != (size_t)len) {
			fclose(file);
			return false;
		}
		fclose(file);
		return true;
	}
	
	inline bool WriteFileDER(const char *fileName) {
		char buf[MAX_BYTES];
		int len = MAX_BYTES;
		if(GetDER(buf, &len) == false)
			return false;
		FILE *file = fopen(fileName, "wb");
		if(!file)
			return false;
		if(fwrite(buf, len, 1, file) != (size_t)len) {
			fclose(file);
			return false;
		}
		fclose(file);
		return true;
	}
	
public:

	inline bool Decrypt(const void *input,
			size_t inputLen,
			void *output,
			size_t *outputLen) {
		if((err = mbedtls_pk_decrypt(&ctx,
					(const uint8_t*)input,
					inputLen,
					(uint8_t*)output,
					outputLen,
					*outputLen,
					RSARandomGeneratorFunction,
					&mtgen)) < 0) {
			return false;
		}
		return true;
	}
	
	inline bool SignHash(const void *hash,
			size_t hashLen,
			void *signature,
			size_t *signatureLen) {
		if((err = mbedtls_pk_sign(&ctx,
					MBEDTLS_MD_SHA512,
					(const uint8_t*)hash,
					hashLen,
					(uint8_t*)signature,
					*signatureLen,
					signatureLen,
					RSARandomGeneratorFunction,
					&mtgen)) < 0) {
			return false;
		}
		return true;
	}

private:

	inline void Init() {
		mbedtls_pk_init(&ctx);
	}

	mbedtls_pk_context ctx;
	std::mt19937_64 mtgen;
};

#include "../generate_key.c"
inline bool GenerateKeys(RSAPrivate& key, RSAPublic& pubkey, int keyBitsLength) {
	
	char argString[1024];
	snprintf(argString, 1024, "nope type=rsa rsa_keysize=%i filename=dup format=pem", keyBitsLength);
	
	int argc = 5;
	char *argv[5];
	argv[0] = strstr(argString, "nope");
	argv[1] = strstr(argString, "type=");
	argv[2] = strstr(argString, "rsa_keysize=");
	argv[3] = strstr(argString, "filename=");
	argv[4] = strstr(argString, "format=");
	for(int i=1; i<5; ++i)
		*(argv[i]-1) = 0;
	
	uint8_t buf[16000];
	size_t len = 16000;
	memset(buf, 0, len);
	
	if(generate_key_main(argc, argv, buf, &len) != 0) {
		printf("\n   Failed generate_key_main()");
		return false;
	}

	buf[len] = 0;
	buf[len+1] = 0;
	if(key.Init(buf, len+1, NULL) == false) {
		printf("\n   Failed key.Init()");
		return false;
	}

	if(key.GetPublic(pubkey) == false) {
		printf("\n   Failed key.GetPublic()");
		return false;
	}

	return true;
}

#endif

