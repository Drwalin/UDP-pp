
#include "pk.h"
#include "sha256.h"
#include "aes.h"

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>

class SHA256 {
public:
	SHA256() {
		Reset();
	}
	SHA256(void *hash, const void *input, size_t bytes) {
		Reset();
		Update(input, bytes);
		Finish(hash);
	}
	SHA256(void *hash, size_t count, ...) {
		Reset();
		va_list vl;
		va_start(vl, count);
		for(size_t i=0; i<count; ++i) {
			const void *input = va_arg(vl, const void*);
			size_t bytes = va_arg(vl, size_t);
			Update(input, bytes);
		}
		va_end(vl);
		Finish(hash);
	}
	~SHA256() {
		memset(&ctx, 0, sizeof(ctx));
	}

	inline void Reset() {
		mbedtls_sha256_starts(&ctx, 0);
	}
	inline void Update(const void *input, size_t bytes) {
		mbedtls_sha256_update(&ctx, (const uint8_t*)input, bytes);
	}
	inline void Finish(void *hash) {
		mbedtls_sha256_finish(&ctx, (uint8_t*)hash);
	}
private:
	mbedtls_sha256_context ctx;
};

class HMACSHA256 {
public:
	inline const static uint64_t i_pad = 0x3636363636363636;
	inline const static uint64_t o_pad = 0x5c5c5c5c5c5c5c5c;

	HMACSHA256(const void *key) {
		Reset(key);
	}
	HMACSHA256(const void *key, void *hmac, const void *input, size_t bytes) {
		Reset(key);
		Update(input, bytes);
		Finish(hmac);
	}
	HMACSHA256(const void* key, void *hmac, size_t count, ...) {
		Reset(key);
		va_list vl;
		va_start(vl, count);
		for(size_t i=0; i<count; ++i) {
			const void *input = va_arg(vl, const void*);
			size_t bytes = va_arg(vl, size_t);
			Update(input, bytes);
		}
		va_end(vl);
		Finish(hmac);
	}
	~HMACSHA256() {
		memset(&ctx, 0, sizeof(ctx));
		memset(okeypad, 0, 256/8);
	}

	inline void Reset(const void *key) {
		mbedtls_sha256_starts(&ctx, 0);
		const uint64_t *key64 = (const uint64_t*)key;

		uint64_t *ikeypad = (uint64_t*)okeypad;
		ikeypad[0] = key64[0] ^ i_pad;
		ikeypad[1] = key64[1] ^ i_pad;
		ikeypad[2] = key64[2] ^ i_pad;
		ikeypad[3] = key64[3] ^ i_pad;
		mbedtls_sha256_update(&ctx, (const uint8_t*)ikeypad, 256/8);

		uint64_t *okeypad = (uint64_t*)(this->okeypad);
		okeypad[0] = key64[0] ^ o_pad;
		okeypad[1] = key64[1] ^ o_pad;
		okeypad[2] = key64[2] ^ o_pad;
		okeypad[3] = key64[3] ^ o_pad;
	}
	inline void Update(const void *input, size_t bytes) {
		mbedtls_sha256_update(&ctx, (const uint8_t*)input, bytes);
	}
	inline void Finish(void *hmac) {
		mbedtls_sha256_finish(&ctx, (uint8_t*)hmac);
		mbedtls_sha256_starts(&ctx, 0);
		mbedtls_sha256_update(&ctx, (const uint8_t*)okeypad, 256/8);
		mbedtls_sha256_update(&ctx, (const uint8_t*)hmac, 256/8);
		mbedtls_sha256_finish(&ctx, (uint8_t*)hmac);
	}
private:
	mbedtls_sha256_context ctx;
	uint8_t okeypad[256/8];
};


class AES256 {
public:
	AES256(const void *key) {
		Reset(key);
	}
	~AES256() {
		memset(&enc, 0, sizeof(enc));
		memset(&dec, 0, sizeof(dec));
	}

	static inline void GenerateIV(void *iv) {
		uint16_t *ivs = (uint16_t*)iv;
		ivs[0] = rand();
		ivs[1] = rand();
		ivs[2] = rand();
		ivs[3] = rand();
		ivs[4] = rand();
		ivs[5] = rand();
		ivs[6] = rand();
		ivs[7] = rand();
	}
	
	inline void Reset(const void *key) {
		mbedtls_aes_init(&enc);
		mbedtls_aes_setkey_enc(&enc, (const uint8_t*)key, 256);

		mbedtls_aes_init(&dec);
		mbedtls_aes_setkey_dec(&dec, (const uint8_t*)key, 256);
	}

	inline void Encrypt(const void *iv, const void *input, void *output, size_t bytes) {
		uint8_t temp[16];
		memcpy(temp, iv, 16);
		mbedtls_aes_crypt_cbc(&enc, MBEDTLS_AES_ENCRYPT, bytes, temp, (const uint8_t*)input, (uint8_t*)output);
	}

	inline void Decrypt(const void *iv, const void *input, void *output, size_t bytes) {
		uint8_t temp[16];
		memcpy(temp, iv, 16);
		mbedtls_aes_crypt_cbc(&dec, MBEDTLS_AES_DECRYPT, bytes, temp, (const uint8_t*)input, (uint8_t*)output);
	}

private:
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
};

class PKPrivate {
public:
	PKPrivate() {
		Init();
	}
	PKPrivate(const void *key, int length) {
		Init();
		Init(key, length);
	}
	~PKPrivate() {
		Clear();
	}

	inline void Clear() {
		
	}


pfrivate:

	inline void Init() {
		mbedtls_pk_init(&ctx);
	}




	mbedtls_pk_context ctx;
};

class PKPublic {
public:



private:



};

void GenerateKeys(PKPrivate& key, PKPublic& pubkey) {
	



}

void PrintHEX(const void *bytes, size_t size) {
	for(size_t i=0; i<size; ++i) {
		printf("%2.2x", (uint32_t)(((uint8_t*)bytes)[i]));
	}
}

int main() {
	
	char hash[32];
	
	char iv[16], iv2[16];
	const char *hmackey = "1234565gfi3j4h5rdgu3habrkjglshabthldhrn4thugnlushbtjh5sey h5uiesongh us5hg9s5nuph5ujpuig reosig resgugshlebtj";
	const char *aeskey = "jfgefefesfrsag4s5 se65 hsrh5 ju 6rdj r6dj 6rd kjdtj 6d jds 6ufiudoshgursdhgiujuHUFGRHUGFIRLHULGru HGURLGHIUR H";
	const char *message = "Pewnej dlugosci wiadomosc dluzsza od 2 blokow AES256\n   Jeszce więcej jakiegoś tekstu który umieszczam w kodzie xDDD, mleko  ";
	const size_t messageLength = strlen(message)+1;

	printf("\n\n Message:\n   %s", message);

	SHA256(hash, message, messageLength);
	printf("\n Message SHA256:\n   ");
	PrintHEX(hash, 32);


	printf("\n\n HMAC key:\n   ");
	PrintHEX(hmackey, 32);
	HMACSHA256(hmackey, hash, message, messageLength);
	printf("\n HMAC of message and hmackey:\n   ");
	PrintHEX(hash, 256/8);


	printf("\n\n\n AES key:\n   ");
	PrintHEX(aeskey, 256/8);

	char ciphertext[1024];
	char decrypted[1024];
	const size_t len = (messageLength>>4)<<4;
	AES256 aes(aeskey);
	AES256::GenerateIV(iv);
	memcpy(iv2, iv, 16);
	aes.Encrypt(iv, message, ciphertext, len);
	aes.Decrypt(iv2, ciphertext, decrypted, len);
	decrypted[len] = 0;
	printf("\n AES ciphertext:\n   ");
	PrintHEX(ciphertext, len);
	printf("\n AES decrypted:\n   %s", decrypted);



	printf("\n");
	return 0;
}




