
#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <ctime>
#include <atomic>
#include <mutex>

#include <IPEndpoint.hpp>
#include <UDPSocket.hpp>
#include <IP.hpp>

std::atomic<int> counter = 0, errors=0;
std::mutex mutex;

void Node(int port, int port2, int port3) {
	ip::udp::Socket socket(port);
	ip::Endpoint endpoint;
	ip::Packet packet;
	socket.SetRecvBufferSize(1024*1024*8);
	socket.SetSendBufferSize(1024*1024*8);
	
 	socket.SetNonblocking(true);
	
	++counter;
	
	while(counter < 3);
	
	int t = clock();
	packet.Write(t);
	packet.Write(port);
	packet.Write(port2);
	if(!socket.Send(packet, ip::GetAddress("127.0.0.1", port2))) {
		printf(" error client send: %s\n", std::strerror(errno));
		errors++;
		return;
	}
	
	packet.Clear();
	t = clock();
	packet.Write(t);
	packet.Write(port);
	packet.Write(port3);
	if(!socket.Send(packet, ip::GetAddress("127.0.0.1", port3))) {
		printf(" error client send: %s\n", std::strerror(errno));
		errors++;
		return;
	}
	
	int received = 0;
	
	for(int i=0; i<2; ++i) {
		int j;
		for(j=0; !socket.Receive(packet, endpoint) && j<100; ++j) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			std::this_thread::yield();
		}
		packet.ResetReading();
		int start = packet.Read<int>();
		int src = packet.Read<int>();
		int dst = packet.Read<int>();
		if(dst == port)
			received++;
		mutex.lock();
		printf(" %i received %i from %i to %i\n", port, start, src, dst);
		mutex.unlock();
	}
	
	if(received != 2) {
		printf(" Error received=%i , errno=%i\n", received, errno);
		errors++;
	}
}

int main() {
	ip::Init();
	for(int i=0; i<1; ++i) {
		counter = 0;
		int ports[3] = {12345,54321,2222};
		std::thread a(Node, ports[0], ports[1], ports[2]);
		std::thread b(Node, ports[1], ports[0], ports[2]);
		Node(ports[2], ports[1], ports[0]);
		a.join();
		b.join();
 		if(i % 231 == 230)
			printf(" Iteration = %i, errors: %i\n", i, errors.load());
	}
	printf(" errors: %i\n", errors.load());
	ip::Deinit();
	printf("\n");
	return 0;
}

