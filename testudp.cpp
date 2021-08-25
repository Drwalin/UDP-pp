
#include <cerrno>
#include <clocale>
#include <stdio.h>	//printf
#include <string.h> //memset
#include <stdlib.h> //exit(0);

#include "src/IPEndpoint.hpp"
#include "src/UDPSocket.cpp"
#include "src/IP.cpp"

#include <thread>
#include <ctime>

void Server() {
	IP::UDP::Socket socket(12345);
	IP::Endpoint endpoint;
	IP::Packet packet;
	if(!socket.Receive(packet, endpoint)) {
		printf(" Error receiving server: %s\n", std::strerror(errno));
		exit(1);
	}
	packet.ResetReading();
	int t = packet.Read<int>();
	/*printf(" Server received from %i.%i.%i.%i:%i (%i timestamp)\n",
			endpoint.address&255,
			(endpoint.address>>8)&255,
			(endpoint.address>>16)&255,
			(endpoint.address>>24)&255,
			endpoint.port,
			t);
	int beg = clock();
	
	int v = 0;
	for(int i=0; i<10000000; ++i) {
		v *= 31;
		v ^= i;
	}
	
	printf(" server time = %i %p\n", t, (void*)(uint64_t)t);
	int end = clock();
	*/
	int diff = 0;//end-beg;
	//printf(" Server diff: %i\n", diff);
	packet.Write(diff);
	packet.Write("Elo", 4);
	if(!socket.Send(packet, endpoint)) {
		printf(" error server send: %s\n", std::strerror(errno));
		exit(311);
	}
}

void Client() {
	int v = 0;
	for(int i=0; i<10000000; ++i) {
		v *= 31;
		v ^= i;
	}
	printf(" Doing client: %i\n", v);
	
	IP::UDP::Socket socket;
	IP::Endpoint endpoint = IP::GetAddress("127.0.0.1", 12345);
	IP::Packet packet;
	int t = clock();
	packet.Write(t);
	printf(" client time = %i %p\n", t, (void*)(uint64_t)t);
	if(!socket.Send(packet, endpoint)) {
		printf(" error client send: %s\n", std::strerror(errno));
		exit(311);
	}
	if(!socket.Receive(packet, endpoint)) {
		printf(" error client receive: %s\n", std::strerror(errno));
		exit(311);
	}
	int End = clock();
	packet.ResetReading();
	int start = packet.Read<int>();
	printf(" client received from %i.%i.%i.%i:%i (%i timestamp)\n",
			endpoint.address&255,
			(endpoint.address>>8)&255,
			(endpoint.address>>16)&255,
			(endpoint.address>>24)&255,
			endpoint.port,
			start);
	int cycling = packet.Read<int>();
	printf(" client diff = %i\n", cycling);
	printf(" Time: %fs  %fs   \"%s\"", (float)cycling/(float)CLOCKS_PER_SEC, 
			(float)(End-start)/(float)CLOCKS_PER_SEC, packet.Buffer()+8);
}

int main() {
	IP::Init();
	std::thread server(Server), client(Client);
	server.join();
	client.join();
	IP::Deinit();
	printf("\n");
	return 0;
}

