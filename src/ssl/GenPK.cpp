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

#include "GenPK.hpp"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>

#include <error.h>
#include <pk.h>
#include <ecdsa.h>
#include <rsa.h>
#include <error.h>
#include <entropy.h>
#include <ctr_drbg.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#define ADD_ARG(_STR) ({ \
		argv[argc] = strstr(argString, _STR); \
		++argc; \
		})

bool GenerateKeys(PKPrivate& key, PKPublic& pubkey, const int keySizeBits, int *err) {
	*err = 0;
	uint8_t buf[16000];
	size_t len = 16000;
	memset(buf, 0, len);

	if(*err = InterGenerateKeys(buf, &len, keySizeBits)) {
		ERROR(*err);
		return false;
	}

	buf[len] = 0;
	buf[len+1] = 0;
	if(key.Init(buf, len+1, NULL) == false) {
		*err = key.err;
		ERROR(*err);
		return false;
	}

	if(key.GetPublic(pubkey) == false) {
		*err = key.err;
		ERROR(*err);
		return false;
	}

	return true;
}

#undef ADD_ARG

int InterGenerateKeys(uint8_t *der, size_t *derLength, const int keySizeBits) {
	int ret = 0;
	mbedtls_pk_context key;
	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "UDP_Drwalin_gen_key";
	int prevLength = *derLength;

	mbedtls_mpi_init(&N); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D); mbedtls_mpi_init(&E); mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);

	mbedtls_pk_init(&key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	memset(der, 0, sizeof(*derLength));

	mbedtls_entropy_init(&entropy);
	if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
					mbedtls_entropy_func,
					&entropy,
					(const uint8_t*) pers,
					strlen(pers)))) {
		ERROR(ret);
		goto _exit;
	}

	if((ret = mbedtls_pk_setup(&key,
					mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))) {
		ERROR(ret);
		goto _exit;
	}

	if((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key),
					mbedtls_ctr_drbg_random,
					&ctr_drbg,
					keySizeBits, 65537))) {
		ERROR(ret);
		goto _exit;
	}

	if((ret = mbedtls_pk_write_key_der(&key, der, *derLength)) < 0) {
		ERROR(ret);
		goto _exit;
	} else {
		*derLength = ret;
		memmove(der, der+prevLength-*derLength, *derLength);
		ret = 0;
	}

_exit:

	mbedtls_mpi_free(&N); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D); mbedtls_mpi_free(&E); mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);

	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return ret;
}

