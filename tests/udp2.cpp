
#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <ctime>
#include <atomic>
#include <mutex>
#include <chrono>

#include <IPEndpoint.hpp>
#include <UDPSocket.hpp>
#include <IP.hpp>

std::atomic<long> errors=0, invalid_sock=0, packet_sent=0, packet_recvd=0, packet_lost=0, sent_errorsss=0, single_sent_err=0;
std::atomic<int> max_j=0;
std::mutex mutex;

void Node(int port, int port2, int port3, std::atomic<long>* counter, std::atomic<long>* invalidSocket) {
	ip::udp::Socket socket(port);
	if(socket.Valid() == false) {
		(*invalidSocket)++;
		++invalid_sock;
		++errors;
		return;
	}
	ip::Endpoint endpoint;
	ip::Packet packet;
	
// 	socket.SetRecvBufferSize(1024*1024);
// 	socket.SetSendBufferSize(1024*1024);
	socket.SetNonblocking(true);
// 	socket.SetTimeout(100);
	
	++(*counter);
	
	while((*counter) < 3 && (*invalidSocket)==0);
	if(*invalidSocket)
		return;
	
	int t = clock();
	packet.Write(t);
	packet.Write(port);
	packet.Write(port2);
	if(!socket.Send(packet, ip::GetAddress("127.0.0.1", port2))) {
		printf(" error client send: %s\n", std::strerror(errno));
		errors++;
		++sent_errorsss;
		++single_sent_err;
		return;
	}
	packet_sent++;
	
	packet.Clear();
	t = clock();
	packet.Write(t);
	packet.Write(port);
	packet.Write(port3);
	if(!socket.Send(packet, ip::GetAddress("127.0.0.1", port3))) {
		printf(" error client send: %s\n", std::strerror(errno));
		errors++;
		++sent_errorsss;
		++single_sent_err;
		return;
	}
	packet_sent++;
	
	int received = 0;
	
	for(int i=0; i<2; ++i) {
		int j=0;
// 		socket.Receive(packet, endpoint);
		bool sol=true;
		for(j=0; !(sol=socket.Receive(packet, endpoint)) && j<10000; ++j) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			std::this_thread::yield();
		}
		if(max_j < j && j < 9900) {
			int prev, max;
			do {
				prev = max_j;
				max = std::max(max_j.load(), j);
			} while(!max_j.compare_exchange_strong(prev, max) && max_j.load() < j);
		}
		packet.ResetReading();
		int start = packet.Read<int>();
		start <<= 0;
		int src = packet.Read<int>();
		int dst = packet.Read<int>();
		if(dst == port && sol) {
			received++;
			packet_recvd++;
		}
// 		mutex.lock();
		if(dst != port) {
// 			printf(" Error (at %i packet.size = %i, j = %i) invalid dst = %i\n", port, packet.size, j, dst);
			packet_lost += 2-received;
			errors++;
			return;
		}
		if(src != port2 && src != port3) {
// 			printf(" Error (at %i packet.size = %i, j = %i) invalid src = %i\n", port, packet.size, j, src);
			packet_lost += 2-received;
			errors++;
			return;
		}
		//printf(" %i received %i from %i to %i\n", port, start, src, dst);
// 		mutex.unlock();
	}
	
	packet_lost += 2-received;
	if(received != 2) {
// 		printf(" Error received=%i , errno=%i\n", received, errno);
		errors++;
		return;
	}
}

const static int COUNT = 100;

int main() {
	ip::Init();
	int ports[COUNT*3];
	for(int j=0; j<COUNT*3; ++j) {
		ports[j] = j+12345; 
	}
	std::thread threads[COUNT*3+10000];
	std::atomic<long> counters[COUNT], invalids[COUNT];
	auto beg = std::chrono::high_resolution_clock::now();
	auto BEG = beg;
	long all_iterations = 100000000ll;
	long prev_sent_err = 0;
	for(long i=0; i<all_iterations;) {
		for(int j=0; j<COUNT*3; j+=3, i++) {
			if(i>=COUNT) {
				threads[j+0].join();
				threads[j+1].join();
				threads[j+2].join();
			}
			
			counters[j/3] = 0;
			invalids[j/3] = 0;
			
			threads[j+0] = std::thread(Node, ports[j+0], ports[j+1], ports[j+2], counters+(j/3), invalids+(j/3));
			threads[j+1] = std::thread(Node, ports[j+1], ports[j+0], ports[j+2], counters+(j/3), invalids+(j/3));
			threads[j+2] = std::thread(Node, ports[j+2], ports[j+1], ports[j+0], counters+(j/3), invalids+(j/3));
			
			auto now = std::chrono::high_resolution_clock::now();
			if((now - beg).count() > 5ll*1000ll*1000ll*1000ll || i==all_iterations || prev_sent_err!=sent_errorsss) {
				prev_sent_err = sent_errorsss;
				int maxj = max_j.load();
				printf(" Iteration = %li, now: %.1f[s], errors: %li, max_j = %i, invalid_sock = %li  packet_loss: %f%% -> lost packets: %li, sent packets: %li, recv packets: %li, wrong sent: %li, wrong sent single err: %li\n",
						i, (float)(now-BEG).count()/(float)(1000l*1000l*1000l), errors.load(), maxj, invalid_sock.load(), (float)(packet_lost.load())*100.0f/(float)((packet_sent.load()!=0)?(long)packet_sent:1ll), packet_lost.load(), packet_sent.load(), packet_recvd.load(), sent_errorsss.load(), single_sent_err.load());
				beg = now;
			}
		}
	}
	for(int i=0; i<COUNT*3; ++i)
		threads[i].join();
	printf(" errors: %li, max_j = %i, invalid_sock = %li\n",
			errors.load(), max_j.load(), invalid_sock.load());
	ip::Deinit();
	printf("\n");
	return 0;
}

