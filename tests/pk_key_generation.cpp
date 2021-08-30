
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

void ClearScreen(void);

template<typename T, typename R>
R Average(const std::vector<T>& data) {
	long double sum = 0.0;
	for(T v : data)
		sum += v;
	return (R)(sum / (long double)data.size());
}

template<typename T, typename R>
R StandardDeviation(const std::vector<T>& data) {
	long double mean, standardDeviation = 0.0;
	mean = Average<T, R>(data);
	for(T v : data)
		standardDeviation += ((long double)v - mean) * ((long double)v - mean);
	return (R)sqrt(standardDeviation / (long double)data.size());
}

template<typename T, typename R>
class ValueMeasures {
public:
	
	ValueMeasures() {
		min = max = avg = stddev = 0;
		data.reserve(1000000);
	}
	
	virtual ~ValueMeasures() {
	}
	
	virtual void Add(T v) {
		std::lock_guard<std::mutex> lock(mutex);
		data.emplace_back(v);
		if(data.size() <= 1) {
			min = max = avg = v;		
			stddev = 0;
		} else {
			max = std::max<T>(max, v);
			min = std::min<T>(min, v);
			avg = Average<T, R>(data);
			stddev = StandardDeviation<T, R>(data);
		}
	}
	
	std::vector<T> data;
	T min;
	T max;
	R avg;
	R stddev;
	std::mutex mutex;
};

template<typename T, typename R>
class TimeMeasures : public ValueMeasures<T, R> {
public:
	
	TimeMeasures() {
	}
	
	virtual ~TimeMeasures() {
	}
	
	std::chrono::time_point<std::chrono::high_resolution_clock> Start() {
		return std::chrono::high_resolution_clock::now();
	}
	
	void End(std::chrono::time_point<std::chrono::high_resolution_clock> start) {
		auto end = Start();
        std::chrono::duration<long double> diff = end- start;
		this->Add(diff.count());
	}
};


TimeMeasures<double, double>
	timeGen,
	timeSign,
	timeVeri,
	timeEncrypt,
	timeDecrypt,
	timeEncode,
	timeDecode;
ValueMeasures<int, int> sizeMeas;

volatile bool running = true;

int bits = 4096;

void ThreadFunc() {
	char buf[mbedtls::MAX_BYTES];
	char buf2[mbedtls::MAX_BYTES];
	size_t size, size2;
	
	decltype(timeGen.Start()) t;
	const static size_t messageSize = 400;

	while(running) {
		PKPrivate key;
		PKPublic pubkey;
		uint32_t err = 0;
		bool b = true;
		
		mbedtls::err = 0;
		t = timeGen.Start();
		err=(err<<1) | (b?0:1); b = GenerateKeys(key, pubkey, bits);
		timeGen.End(t);
		if(!b) MBEDTLS_ERROR();
		
		mbedtls::err = 0;
		size2 = size = mbedtls::MAX_BYTES;
		mbedtls::Random(NULL, buf, messageSize);
		buf[0] = 0;
		t = timeEncrypt.Start();
		err=(err<<1) | (b?0:1); b = pubkey.Encrypt(buf, messageSize, buf2, &size2);
		timeEncrypt.End(t);
		if(!b) MBEDTLS_ERROR();
		
		mbedtls::err = 0;
		t = timeDecrypt.Start();
		err=(err<<1) | (b?0:1); b = key.Decrypt(buf2, size2, buf, &size);
		timeDecrypt.End(t);
		if(!b) MBEDTLS_ERROR();
		
		mbedtls::err = 0;
		size2 = mbedtls::MAX_BYTES;
		t = timeSign.Start();
		err=(err<<1) | (b?0:1); b = key.SignHash(buf, 64, buf2, &size2);
		timeSign.End(t);
		if(!b) MBEDTLS_ERROR();
		
		mbedtls::err = 0;
		t = timeVeri.Start();
		err=(err<<1) | (b?0:1); b = pubkey.VerifyHash(buf, 64, buf2, size2);
		timeVeri.End(t);
		if(!b) MBEDTLS_ERROR();
		
		mbedtls::err = 0;
		t = timeEncode.Start();
		size = mbedtls::MAX_BYTES;
		for(int i=0; i<1000; ++i) {
			err=(err<<1) | (b?0:1); b = pubkey.GetDER((void*)buf, (int*)&size);
		}
		timeEncode.End(t);
		if(!b) MBEDTLS_ERROR();
		
		sizeMeas.Add(size);
		
		mbedtls::err = 0;
		t = timeDecode.Start();
		for(int i=0; i<1000; ++i) {
			err=(err<<1) | (b?0:1); b = pubkey.Init(buf, size);
		}
		timeDecode.End(t);
		if(!b) MBEDTLS_ERROR();
		
		err=(err<<1) | (b?0:1);
		if(err)
			printf("\n error: %X", err);
	}
}

int main(int argc, char **argv) {
	unsigned max_threads = std::thread::hardware_concurrency();
	if(max_threads > 2)
		max_threads -= 1;
	if(max_threads > 8)
		max_threads -= 1;
	if(argc > 1)
		max_threads = atoi(argv[1]);
	if(argc > 2)
		bits = atoi(argv[2]);
	ClearScreen();
	
	std::vector<std::thread> threads;
	for(unsigned i=0; i<max_threads; ++i) {
		threads.emplace_back(ThreadFunc);
	}
	
	printf("\n Hardware threads: %u", max_threads);
	printf("\n Using threads: %u", max_threads);
	printf("\n Using bits: %i", bits);
	while(running) {
		
		std::this_thread::sleep_for(std::chrono::seconds(1));
		ClearScreen();
		
		printf("\n Hardware threads: %u", max_threads);
		printf("\n Using threads: %u", max_threads);
		printf("\n Using bits: %i", bits);
		
		printf("\n count: %lli\n", (int64_t)timeGen.data.size());
		printf("\n test             avg         max        stddev");
		printf("\n size             %3i         %3i         %3i", sizeMeas.min, sizeMeas.avg, sizeMeas.max, sizeMeas.stddev);
		printf("\n timeGen         %.2f        %.2f        %.2f", timeGen.avg, timeGen.max, timeGen.stddev);
		printf("\n timeSign      %2.2e    %2.2e    %2.2e", timeSign.avg, timeSign.max, timeSign.stddev);
		printf("\n timeVeri      %2.2e    %2.2e    %2.2e", timeVeri.avg, timeVeri.max, timeVeri.stddev);
		printf("\n timeEncrypt   %2.2e    %2.2e    %2.2e", timeEncrypt.avg, timeEncrypt.max, timeEncrypt.stddev);
		printf("\n timeDecrypt   %2.2e    %2.2e    %2.2e", timeDecrypt.avg, timeDecrypt.max, timeDecrypt.stddev);
		printf("\n timeEncode    %2.2e    %2.2e    %2.2e", timeEncode.avg*0.001, timeEncode.max*0.001, timeEncode.stddev*0.001);
		printf("\n timeDecode    %2.2e    %2.2e    %2.2e", timeDecode.avg*0.001, timeDecode.max*0.001, timeDecode.stddev*0.001);
		printf("\n");
	}
	
	printf("\n");
	for(std::thread& t : threads)
		t.join();
	
	return 0;
}


#ifdef _WIN32
#include <windows.h>
void ClearScreen(void) {
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD topLeft = {0, 0};
	DWORD dwCount, dwSize;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hOutput, &csbi);
	dwSize = csbi.dwSize.X * csbi.dwSize.Y;
	FillConsoleOutputCharacter(hOutput, 0x20, dwSize, topLeft, &dwCount);
	FillConsoleOutputAttribute(hOutput, 0x07, dwSize, topLeft, &dwCount);
	SetConsoleCursorPosition(hOutput, topLeft);
}
#else
#include <stdio.h>
void ClearScreen(void) {
	printf("\x1B[2J");
}
#endif

