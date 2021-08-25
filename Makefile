
run_testmbedtls: testmbedtls.exe
	./testmbedtls.exe

run_testudp: testudp.exe 
	./testudp.exe

testudp.exe: src/IP.cpp src/UDPSocket.cpp src/UDPSocket.hpp testudp.cpp src/OSCheck.hpp src/IPPacket.hpp src/IP.cpp src/IPEndpoint.hpp
	g++ -o testudp.exe testudp.cpp -lpthread

testmbedtls.exe: testmbedtls.cpp mbedtls/library/libmbedcrypto.a
	g++ -o testmbedtls.exe testmbedtls.cpp mbedtls/library/libmbedcrypto.a -Imbedtls/include -Imbedtls/include/mbedtls -ggdb3 -Og

mbedtls/library/libmbedcrypto.a: mbedtls/library/aes.c mbedtls/library/sha256.c mbedtls/library/rsa.c
	cd mbedtls && make lib

