
CFLAGS = -Og -ggdb3 -Wl,--gc-sections -Wall -pedantic -static -fno-exceptions -fno-rtti -fPIE -ffast-math -Imbedtls/include -Imbedtls/include/mbedtls
CXXFLAGS = $(CFLAGS) -std=c++17

run_testmbedtls: testmbedtls.exe
	./testmbedtls.exe

run_testudp: testudp.exe 
	./testudp.exe

testudp.exe: src/IP.cpp src/UDPSocket.cpp src/UDPSocket.hpp testudp.cpp src/OSCheck.hpp src/IPPacket.hpp src/IP.cpp src/IPEndpoint.hpp
	g++ -o testudp.exe testudp.cpp -lpthread $(CXXFLAGS)

testmbedtls.exe: testmbedtls.cpp libmbedcrypto.a generate_key.c src/RSA.hpp src/SHA256.hpp src/SHA512.hpp src/AES256.hpp src/HMACSHA256.hpp
	g++ -o testmbedtls.exe testmbedtls.cpp libmbedcrypto.a $(CXXFLAGS)

mbedtls/library/libmbedcrypto.a: mbedtls/library/aes.c mbedtls/library/sha256.c mbedtls/library/rsa.c mbedtls/library/pk.c
	cd mbedtls && make lib


OBJS_CRYPTO= \
	     aes.o \
	     aesni.o \
	     aria.o \
	     asn1parse.o \
	     asn1write.o \
	     base64.o \
	     bignum.o \
	     camellia.o \
	     ccm.o \
	     chacha20.o \
	     chachapoly.o \
	     cipher.o \
	     cipher_wrap.o \
	     cmac.o \
	     ctr_drbg.o \
	     des.o \
	     dhm.o \
	     ecdh.o \
	     ecdsa.o \
	     ecjpake.o \
	     ecp.o \
	     ecp_curves.o \
	     entropy.o \
	     entropy_poll.o \
	     error.o \
	     gcm.o \
	     hkdf.o \
	     hmac_drbg.o \
	     md.o \
	     md5.o \
	     memory_buffer_alloc.o \
	     mps_reader.o \
	     mps_trace.o \
	     nist_kw.o \
	     oid.o \
	     padlock.o \
	     pem.o \
	     pk.o \
	     pk_wrap.o \
	     pkcs12.o \
	     pkcs5.o \
	     pkparse.o \
	     pkwrite.o \
	     platform.o \
	     platform_util.o \
	     poly1305.o \
	     psa_crypto.o \
	     psa_crypto_aead.o \
	     psa_crypto_cipher.o \
	     psa_crypto_client.o \
	     psa_crypto_driver_wrappers.o \
	     psa_crypto_ecp.o \
	     psa_crypto_hash.o \
	     psa_crypto_mac.o \
	     psa_crypto_rsa.o \
	     psa_crypto_se.o \
	     psa_crypto_slot_management.o \
	     psa_crypto_storage.o \
	     psa_its_file.o \
	     ripemd160.o \
	     rsa.o \
	     rsa_alt_helpers.o \
	     sha1.o \
	     sha256.o \
	     sha512.o \
	     threading.o \
	     timing.o \
	     version.o \
	     version_features.o \
	     # This line is intentionally left blank

OBJS_CRYPTO_BUILTIN = $(addprefix mbedtls/library/, $(OBJS_CRYPTO))


libmbedcrypto.a: $(OBJS_CRYPTO_BUILTIN)
	ar -crs libmbedcrypto.a $(OBJS_CRYPTO_BUILTIN)

mbedtls/library/%.o: mbedtls/library/%.c
	gcc -c $(CFLAGS) -o $@ $< -Imbedtls/library

