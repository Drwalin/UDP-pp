
#include <GenPK.hpp>
#include <Util.hpp>

#include <error.h>
#include <pk.h>

#include <cmath>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <cstring>

#include <vector>
#include <map>
#include <chrono>
#include <algorithm>
#include <mutex>
#include <thread>
#include <string>
#include <atomic>

template<typename T>
T Average(const std::vector<T>& data) {
	T sum = 0.0;
	for(T v : data)
		sum += v;
	return sum / (T)data.size();
}

template<typename T>
T StandardDeviation(const std::vector<T>& data) {
	T mean, standardDeviation = 0.0;
	mean = Average<T>(data);
	for(T v : data)
		standardDeviation += (v - mean) * (v - mean);
	return sqrt(standardDeviation / (T)data.size());
}


std::mutex mutex;

std::map<int, size_t> sizes;
std::vector<long double> times, sizesArr;

volatile double sizeAvg;
volatile double sizeDev;
volatile int sizeMax = 0;

volatile double timeAvg;
volatile double timeDev;
volatile long double timeMax = 0.0f;

volatile bool running = true;

int bits = 4096;

void ThreadFunc() {
	char buf[mbedtls::MAX_BYTES];
	size_t size;

	while(running) {
		auto start = std::chrono::system_clock::now();
		PKPrivate key;
		PKPublic pubkey;
		GenerateKeys(key, pubkey, bits);
		
        auto finish = std::chrono::system_clock::now();
        std::chrono::duration<long double> diff = finish - start;
		
		size = mbedtls::MAX_BYTES;
		pubkey.GetDER((void*)buf, (int*)&size);
		
		std::lock_guard<std::mutex> lock(mutex);
		
		if(sizes.count(size) == 0)
			sizes[size] = 1;
		else
			sizes[size]++;
		
		times.emplace_back(diff.count());
		sizesArr.emplace_back((long double)size);
		
		timeMax = std::max<long double>(diff.count(), (long double)timeMax);
		sizeMax = std::max<int>(size, (long double)sizeMax);
		
		sizeAvg = Average(sizesArr);
		sizeDev = StandardDeviation(sizesArr);
		timeAvg = Average(times);
		timeDev = StandardDeviation(times);
	}
}

int main(int argc, char **argv) {
	times.reserve(1000000);
	sizesArr.reserve(1000000);
	
	unsigned max_threads = std::thread::hardware_concurrency();
	printf("\n Hardware threads: %u", max_threads);
	if(max_threads > 2)
		max_threads -= 3;
	if(argc > 1)
		max_threads = atoi(argv[1]);
	printf("\n Using threads: %u\n", max_threads);
	
	if(argc > 2)
		bits = atoi(argv[2]);
	
	std::vector<std::thread> threads;
	for(unsigned i=0; i<max_threads; ++i) {
		threads.emplace_back(ThreadFunc);
	}
	
	printf("\n          |       size [B]     |      time [s]");
	printf("\n   tests  |   avg  stddev  max |  avg  stddev  max");
	printf("\n");
	while(running) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		printf("\r%6ld    |   %.0f   %.1f  %5i |  %.2f  %.2f   %.2f  ",
				(long)times.size(),
				sizeAvg,
				sizeDev,
				sizeMax,
				timeAvg,
				timeDev,
				(double)timeMax);
	}
	
	printf("\n");
	for(std::thread& t : threads)
		t.join();
	
	return 0;
}

