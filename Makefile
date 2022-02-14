
include MakefileSTD/MakefileSTD

CXX=g++
CC=gcc

INCLUDES= \
		  -Imbedtls/include \
		  -Imbedtls/include/mbedtls \
		  -Isrc/ip \
		  -Isrc/ssl \
		  -Isrc

CFLAGS= $(INCLUDES) \
		-O4 -s \
		-pedantic -Wall

LIBS= -lpthread libmbedcrypto.a
ifeq ($(platform),win)
	LIBS += -lws2_32
else
endif

CXXFLAGS=$(CFLAGS) -std=c++17


test: ecdh tests mbedtls udp udp2 ntp


aes_hmac_benchmark: tests/aes_hmac_benchmark.exe
	tests/aes_hmac_benchmark.exe

pk_benchmark: tests/pk_benchmark.exe
	tests/pk_benchmark.exe

mbedtls: tests/mbedtls.exe
	./tests/mbedtls.exe

udp: tests/udp.exe 
	./tests/udp.exe

ecdh: tests/ecdh.exe 
	./tests/ecdh.exe

udp2: tests/udp2.exe 
	./tests/udp2.exe

ntp: tests/ntp.exe 
	./tests/ntp.exe

tests: tests/mbedtls.exe tests/udp2.exe tests/udp.exe tests/ntp.exe tests/ecdh.exe
benchmarks: tests/pk_benchmark.exe tests/aes_hmac_benchmark.exe



_HEADERS_IP= \
			IP.hpp \
			IPEndpoint.hpp \
			IPPacket.hpp \
			NTP.hpp \
			UDPSocket.hpp \
			OSCheck.hpp
HEADERS_IP=$(addprefix src/ip/, $(_HEADERS_IP))

_OBJS_IP= \
		  IP.o \
		  NTP.o \
		  UDPSocket.o
OBJS_IP=$(addprefix obj/src/ip/, $(_OBJS_IP))

_HEADERS_SSL= \
			 AES256.hpp \
			 SHA256.hpp \
			 SHA512.hpp \
			 PK.hpp \
			 HMACSHA256.hpp \
			 GenPK.hpp \
			 Util.hpp
HEADERS_SSL=$(addprefix src/ssl/, $(_HEADERS_SSL))

_OBJS_SSL= \
		  PK.o \
		  GenPK.o \
		  Util.o
OBJS_SSL=$(addprefix obj/src/ssl/, $(_OBJS_SSL))

HEADERS=$(HEADERS_SSL) $(HEADERS_IP)
OBJS=$(OBJS_SSL) $(OBJS_IP)

.PRECIOUS: $(OBJS) libmbedcrypto.a


tests/%.exe: obj/tests/%.o $(HEADERS) $(OBJS) libmbedcrypto.a
	$(CXX) -o $@ $(CXXFLAGS) $< $(OBJS) $(LIBS)


#tests/udp.exe: $(HEADERS) obj/tests/udp.o libmbedcrypto.a $(OBJS)
#	$(CXX) -o $@ $(CXXFLAGS) obj/tests/udp.o $(OBJS) $(LIBS)

#tests/mbedtls.exe: $(OBJS_SSL) obj/tests/mbedtls.o libmbedcrypto.a $(HEADERS_SSL)
#	$(CXX) -o $@ $(CXXFLAGS) obj/tests/mbedtls.o $(OBJS_SSL) $(LIBS)

#tests/pk_benchmark.exe: $(OBJS_SSL) obj/tests/pk_benchmark.o libmbedcrypto.a $(HEADERS_SSL)
#	$(CXX) -o $@ $(CXXFLAGS) obj/tests/pk_benchmark.o $(OBJS_SSL) $(LIBS)

#tests/aes_hmac_benchmark.exe: $(OBJS_SSL) obj/tests/aes_hmac_benchmark.o libmbedcrypto.a $(HEADERS_SSL)
#	$(CXX) -o $@ $(CXXFLAGS) obj/tests/aes_hmac_benchmark.o $(OBJS_SSL) $(LIBS)



obj/src/ip/%.o: src/ip/%.cpp $(HEADERS_IP)
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

obj/src/ssl/%.o: src/ssl/%.cpp $(HEADERS_SSL)
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

obj/tests/%.o: tests/%.cpp tests/Benchmarking.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

obj/programs/%.o: programs/%.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) 



_OBJS_CRYPTO= \
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
	     version_features.o
OBJS_CRYPTO=$(addprefix mbedtls/library/, $(_OBJS_CRYPTO))


libmbedcrypto.a: $(OBJS_CRYPTO)
	ar -crs libmbedcrypto.a $(OBJS_CRYPTO)

mbedtls/library/%.o: mbedtls/library/%.c
	$(CC) -c $(CFLAGS) -o $@ $< -Imbedtls/library


.PHONY: clean_mbedtls
clean_mbedtls:
	$(RM) libmbedcrypto.a
	$(RM) mbedtls$(S)library$(S)*.o

.PHONY: clean
clean:
	$(RM) obj$(S)tests$(S)*.o
	$(RM) obj$(S)programs$(S)*.o
	$(RM) obj$(S)src$(S)ip$(S)*.o
	$(RM) obj$(S)src$(S)ssl$(S)*.o
	$(RM) programs$(S)*.exe
	$(RM) tests$(S)*.exe

.PHONY: clean_all
clean_all:
	$(RM) obj$(S)tests$(S)*.o
	$(RM) obj$(S)programs$(S)*.o
	$(RM) obj$(S)src$(S)ip$(S)*.o
	$(RM) obj$(S)src$(S)ssl$(S)*.o
	$(RM) mbedtls$(S)library$(S)*.o
	$(RM) programs$(S)*.exe
	$(RM) tests$(S)*.exe
	$(RM) libmbedcrypto.a

