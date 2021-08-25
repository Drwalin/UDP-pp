
run: testudp.exe
	./testudp.exe

testudp.exe: src/IP.cpp src/UDPSocket.cpp src/UDPSocket.hpp testudp.cpp src/OSCheck.hpp src/IPPacket.hpp src/IP.cpp src/IPEndpoint.hpp
	g++ -o testudp.exe testudp.cpp -lpthread
