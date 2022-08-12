
#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <ctime>

#include <IPEndpoint.hpp>
#include <UDPSocket.hpp>
#include <IP.hpp>

void Server() {
	ip::udp::Socket socket(12345);
	ip::Endpoint endpoint;
	ip::Packet packet;
	if(!socket.Receive(packet, endpoint)) {
		printf(" Error receiving server: %s\n", std::strerror(errno));
		exit(1);
	}
	packet.ResetReading();
	packet.Read<int>();
	int diff = 0;
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
	
	ip::udp::Socket socket;
	ip::Endpoint endpoint = ip::GetAddress("127.0.0.1", 12345);
	ip::Packet packet;
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
	printf(" client received from %s (%i timestamp)\n",
			endpoint.ToString().c_str(),
			start);
	int cycling = packet.Read<int>();
	printf(" client diff = %i\n", cycling);
	printf(" Time: %fs  %fs   \"%s\"", ((float)cycling)/(float)CLOCKS_PER_SEC, 
			(float)(End-start)/(float)CLOCKS_PER_SEC, packet.Buffer()+8);
}

int main() {
	ip::Init();
	std::thread server(Server), client(Client);
	server.join();
	client.join();
	ip::Deinit();
	printf("\n");
	return 0;
}

