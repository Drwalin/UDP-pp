
#include <PK.hpp>
#include <SHA256.hpp>
#include <SHA512.hpp>
#include <HMACSHA256.hpp>
#include <AES256.hpp>
#include <GenPK.hpp>

#include <error.h>

#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>

void PrintHEX(const void *bytes, size_t size) {
	for(size_t i=0; i<size; ++i) {
		printf(" %2.2x", (uint32_t)(((uint8_t*)bytes)[i]));
	}
}

int main() {
	
	char hash[32];
	char iv[16], iv2[16];
	const char *hmackey = "1234565gfi3j4h5rdgu3habrkjglshabthldhrn4thugnlushbtjh5sey h5uiesongh us5hg9s5nuph5ujpuig reosig resgugshlebtj";
	const char *aeskey = "jfgefefesfrsag4s5 se65 hsrh5 ju 6rdj r6dj 6rd kjdtj 6d jds 6ufiudoshgursdhgiujuHUFGRHUGFIRLHULGru HGURLGHIUR H";
	const char *_message = "\0Pewnej dlugosci wiadomosc dluzsza od 2 blokow AES256\n   Jeszce więcej jakiegoś tekstu który umieszczam w kodzie xDDD, mleko  \0\0\0\0\0\0\0";
	const char *message = _message+1;
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

	char ciphertext[16000];
	char decrypted[16000];
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

	
	
	printf("\n\n\n PK:");
	PKPrivate key;
	PKPublic pubkey;
	int err;
	if(GenerateKeys(key, pubkey, 4096, &err) == false) {
		ERROR(err);
		printf("\n   invalid keys\n");
		return 1;
	}
	
	int pemlen = 16000;
	pubkey.GetPEM(ciphertext, &pemlen);
	printf("\n  PEM Public key (%ib):\n   `%s`\n", pemlen, ciphertext);
	int derlen = 16000;
	pubkey.GetDER(ciphertext, &derlen);
	printf("\n  DER Public key (%ib):\n   ", derlen);
	PrintHEX(ciphertext, derlen);
	
	
	size_t cipherTextLength = 16000;
	if(!pubkey.Encrypt(_message, messageLength+1, ciphertext, &cipherTextLength)) {
		printf("\n   Invalid PKPublic::Encrypt\n");
		return 2;
	}
	printf("\n\n PK ciphertext (%i bytes)\n   ", (int)cipherTextLength);
	PrintHEX(ciphertext, cipherTextLength);
	
	size_t decryptedLength = 16000;
	if(!key.Decrypt(ciphertext, cipherTextLength, decrypted, &decryptedLength)) {
		printf("\n   Invalid PKPrivate::Decrypt\n");
		return 2;
	}
	printf("\n\n PK decrypted message (%i bytes)\n   %s\n", (int)decryptedLength, decrypted+1);
	
	
	printf("\n\n\n PK signing:");
	char sha512[64];
	SHA512(sha512, message, messageLength);
	size_t signatureLen = 16000;
	key.SignHash(sha512, 64, ciphertext, &signatureLen);
	printf("\n\n PK signature (%i bytes)\n   ", (int)signatureLen);
	PrintHEX(ciphertext, signatureLen);
	
	
	
	if(pubkey.VerifyHash(sha512, 64, ciphertext, signatureLen)) {
		printf("\n signature valid - good");
	} else {
		printf("\n signature invalid - CRITICAL ERROR");
	}
	
	
	sha512[0]++;
	if(pubkey.VerifyHash(sha512, 64, ciphertext, signatureLen)) {
		printf("\n signature valid - CRITICAL ERROR");
	} else {
		printf("\n signature invalid - good");
	}
	
	

	printf("\n");
	return 0;
}

