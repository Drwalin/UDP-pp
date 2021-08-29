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

#include "PK.hpp"

#include <pk.h>
#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

int PKRandomGeneratorFunction(void* _gen, unsigned char* buf, size_t len) {
	std::mt19937_64 &gen = *(std::mt19937_64*)_gen;
	for(unsigned char *end=buf+len; buf!=end; ++buf) {
		*buf = gen();
	}
	return 0;
}


PKPublic::PKPublic() {
	Init();
}

PKPublic::PKPublic(const void *key, int length) {
	Init();
	Init(key, length);
}

PKPublic::PKPublic(const char *keyFileName) {
	Init();
	Init(keyFileName);
}

PKPublic::~PKPublic() {
	Clear();
}


void PKPublic::Clear() {
	mbedtls_pk_free(&ctx);
}

bool PKPublic::Init(const void *key, int length) {
	Clear();
	Init();
	return !((err = mbedtls_pk_parse_public_key(&ctx,
					(const uint8_t*)key, length)) < 0);
}

bool PKPublic::Init(const char *keyFileName) {
	Clear();
	Init();
	return !((err = mbedtls_pk_parse_public_keyfile(&ctx,
					keyFileName)) < 0);
}

bool PKPublic::GetDER(void *buf, int *len) {
	int orgLen = *len;
	err = *len = mbedtls_pk_write_pubkey_der(&ctx, (uint8_t*)buf, *len);
	if(*len < 0)
		return false;
	if(orgLen != *len)
		memmove(buf, (uint8_t*)buf+orgLen-*len, *len);
	return true;
}

bool PKPublic::GetPEM(char *buf, int *len) {
	err = mbedtls_pk_write_pubkey_pem(&ctx, (uint8_t*)buf, *len);
	if(err < 0)
		return false;
	*len = strlen(buf)+1;
	return true;
}

bool PKPublic::WriteFilePEM(const char *fileName) {
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

bool PKPublic::WriteFileDER(const char *fileName) {
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


bool PKPublic::Encrypt(const void *input,
		size_t inputLen,
		void *output,
		size_t *outputLen) {
	return !((err = mbedtls_pk_encrypt(&ctx,
					(const uint8_t*)input,
					inputLen,
					(uint8_t*)output,
					outputLen,
					*outputLen,
					PKRandomGeneratorFunction,
					&mtgen)) < 0);
}

bool PKPublic::VerifyHash(const void *hash,
		size_t hashLen,
		const void *signature,
		size_t signatureLen) {
	return !((err = mbedtls_pk_verify(&ctx,
					MBEDTLS_MD_SHA512,
					(const uint8_t*)hash,
					hashLen,
					(uint8_t*)signature,
					signatureLen)) < 0);
}


void PKPublic::Init() {
	mbedtls_pk_init(&ctx);
}



PKPrivate::PKPrivate() {
	Init();
}

PKPrivate::PKPrivate(const void *key, int length, const char *password) {
	Init();
	Init(key, length, password);
}

PKPrivate::PKPrivate(const char *keyFileName, const char *password) {
	Init();
	Init(keyFileName, password);
}

PKPrivate::~PKPrivate() {
	Clear();
}


void PKPrivate::Clear() {
	mbedtls_pk_free(&ctx);
}

bool PKPrivate::Init(const void *key, int length, const char *password) {
	Clear();
	return !((err = mbedtls_pk_parse_key(&ctx,
					(const uint8_t*)key,
					length,
					(const uint8_t*)password,
					password ? strlen(password) : 0,
					PKRandomGeneratorFunction,
					&mtgen)) < 0);
}

bool PKPrivate::Init(const char *keyFileName, const char *password) {
	Clear();
	Init();
	return !((err = mbedtls_pk_parse_keyfile(&ctx,
					keyFileName,
					password,
					PKRandomGeneratorFunction,
					&mtgen)) < 0);
}

bool PKPrivate::GetPublic(PKPublic& pubkey) {
	char buf[MAX_BYTES];
	int len = MAX_BYTES;
	err = len = mbedtls_pk_write_pubkey_der(&ctx, (uint8_t*)buf, len);
	if(err < 0)
		return false;
	return pubkey.Init(buf+MAX_BYTES-len, len);
}

bool PKPrivate::GetDER(void *buf, int *len) {
	int orgLen = *len;
	err = *len = mbedtls_pk_write_key_der(&ctx, (uint8_t*)buf, *len);
	if(*len < 0)
		return false;
	if(orgLen != *len)
		memmove(buf, (uint8_t*)buf+orgLen-*len, *len);
	return true;
}

bool PKPrivate::GetPEM(char *buf, int *len) {
	err = mbedtls_pk_write_key_pem(&ctx, (uint8_t*)buf, *len);
	if(err < 0)
		return false;
	*len = strlen(buf)+1;
	return true;
}

bool PKPrivate::WriteFilePEM(const char *fileName) {
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

bool PKPrivate::WriteFileDER(const char *fileName) {
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


bool PKPrivate::Decrypt(const void *input,
		size_t inputLen,
		void *output,
		size_t *outputLen) {
	return !((err = mbedtls_pk_decrypt(&ctx,
					(const uint8_t*)input,
					inputLen,
					(uint8_t*)output,
					outputLen,
					*outputLen,
					PKRandomGeneratorFunction,
					&mtgen)) < 0);
}

bool PKPrivate::SignHash(const void *hash,
		size_t hashLen,
		void *signature,
		size_t *signatureLen) {
	return !((err = mbedtls_pk_sign(&ctx,
					MBEDTLS_MD_SHA512,
					(const uint8_t*)hash,
					hashLen,
					(uint8_t*)signature,
					*signatureLen,
					signatureLen,
					PKRandomGeneratorFunction,
					&mtgen)) < 0);
}


void PKPrivate::Init() {
	mbedtls_pk_init(&ctx);
}

