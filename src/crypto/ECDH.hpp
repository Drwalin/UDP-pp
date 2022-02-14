/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2022 Marek Zalewski aka Drwalin
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

#include <../../mbedtls/include/mbedtls/ecdh.h>
#include <ecdh.h>
#include <error.h>

#include <vector>
#include <cstring>
#include <errno.h>

#include "Random.hpp"

#define ERR(RES) {errno=RES; if(errno!=0) printf(" mbedtls error(%i) = %s  %s:%i\n", errno, mbedtls_high_level_strerr(errno), __FILE__, __LINE__);}

namespace crypto {
	class ECDH {
	public:
		
		ECDH(const ECDH&) = delete;
		ECDH(ECDH&) = delete;
		ECDH(ECDH&&) = delete;
		ECDH& operator=(const ECDH&) = delete;
		ECDH& operator=(ECDH&) = delete;
		ECDH& operator=(ECDH&&) = delete;
		
		inline ECDH() {
			mbedtls_ecdh_init(&ctx);
		}
		inline ~ECDH() {
			mbedtls_ecdh_free(&ctx);
		}
		
		inline size_t GenerateKeyPair() {
			size_t olen = 0;
			ERR(mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1));
			const int KEYPAIR_MAX_SIZE = 1000;
			pubkey.resize(KEYPAIR_MAX_SIZE);
			ERR(mbedtls_ecdh_make_params(&ctx, &olen, pubkey.data(),
						pubkey.size(),
					Random, this));
			if(errno)
				olen = 0;
			pubkey.resize(olen);
			return pubkey.size();
		}
		
		inline size_t GetPublicKeySize() {
			return pubkey.size();
		}
		
		inline size_t GetPublicKey(void* buffer) {
			memcpy(buffer, pubkey.data(), pubkey.size());
			return pubkey.size();
		}
		
		inline size_t GetSharedSecretKeySize() {
			return 1024;
			// TODO: WTF?!?!?!
			// TODO: correct?
			// TODO: mbedtls is unclear wtf is it?
		}
		
		inline size_t DerieveSharedSecret(const void* otherPublicKey,
				size_t otherKeySize, void* sharedSecret) {
			ERR(mbedtls_ecdh_read_params(&ctx, (const uint8_t**)&otherPublicKey,
					(const uint8_t*)otherPublicKey+otherKeySize));
			size_t olen = 0;
			ERR(mbedtls_ecdh_calc_secret(&ctx, &olen, (uint8_t*)sharedSecret,
					GetSharedSecretKeySize(), &Random, this));
			return olen;
		}
		
	private:
		
		mbedtls_ecdh_context ctx;
		std::vector<uint8_t> pubkey;
	};
}

