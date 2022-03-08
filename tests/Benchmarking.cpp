
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

#include <OSCheck.hpp>

#ifdef OS_WINDOWS
#include <windows.h>
void gotoxy(int XPos, int YPos) {
	COORD coord;
	coord.X = XPos; coord.Y = YPos;
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),coord);
}
void clrscr(void) {
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
void gotoxy(int XPos, int YPos) {
	printf("\033[%d;%dH",YPos+1,XPos+1);
}
void clrscr(void) {
	printf("\x1B[2J");
}
#endif

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
R StandardDeviationInv(const std::vector<T>& data) {
	long double mean, standardDeviation = 0.0;
	mean = 1.0/Average<T, R>(data);
	for(T v : data)
		standardDeviation += (1.0/(long double)v - mean) * (1.0/(long double)v - mean);
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
			stddevinv = StandardDeviationInv<T, R>(data);
		}
	}
	
	virtual void PrintE(const char *name, size_t iterations) {
		Init(name);
		long double mul = 1.0 / (long double)iterations;
		printf("%2.2e    %2.2e    %2.2e", (float)(avg*mul), (float)(max*mul), (float)(stddev*mul));
		printf("         ");
	}
	
	virtual void PrintInverseE(const char *name, long double ops) {
		Init(name);
		long double mul = ops;
		printf("%2.2e    %2.2e    %2.2e", (float)(mul/avg), (float)(mul/max), (float)(mul*stddevinv));
		printf("         ");
	}
	
	virtual void PrintInverseF(const char *name, long double ops) {
		Init(name);
		long double mul = ops;
		printf("%7.2f     %7.2f     %7.2f", (float)(mul/avg), (float)(mul/max), (float)(mul/stddevinv));
		printf("         ");
	}
	
	virtual void PrintF(const char *name, size_t iterations) {
		Init(name);
		long double mul = 1.0 / (long double)iterations;
		printf("  %7.2f     %7.2f     %7.2f", (float)(avg*mul), (float)(max*mul), (float)(stddev*mul));
		printf("         ");
	}
	
	virtual void PrintI(const char *name, size_t iterations) {
		Init(name);
		long double mul = 1.0 / (long double)iterations;
		printf("   %3i         %3i         %3i", (int)(min*mul), (int)(avg*mul), (int)(max*mul));
		printf("         ");
	}
	
	virtual void Init(const char *name) {
		int len = strlen(name);
		printf("\n %s", name);
		for(int i=len; i<20; ++i) {
			printf(" ");
		}
	}
	
	std::vector<T> data;
	T min;
	T max;
	R avg;
	R stddev;
	R stddevinv;
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

volatile bool running = true;

template<typename T>
void BenchmarkFunction(void(*Function)(T&)) {
	T args;
	while(running) {
		Function(args);
		if(mbedtls::err) {
			MBEDTLS_ERROR();
		}
	}
}

template<typename T>
void BenchmarkMain(int argc, char **argv, void(*Function)(T&), void (*Print)()) {
	clrscr();
	running = true;
	
	unsigned max_threads = std::thread::hardware_concurrency();
	if(max_threads > 2)
		max_threads -= 1;
	if(max_threads > 8)
		max_threads -= 1;
	if(argc > 1)
		max_threads = atoi(argv[1]);
	
	std::vector<std::thread> threads;
	for(unsigned i=0; i<max_threads; ++i) {
		threads.emplace_back(BenchmarkFunction<T>, Function);
	}
	
	std::this_thread::sleep_for(std::chrono::seconds(1));
	while(running) {
		Print();
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
	
	printf("\n");
	for(std::thread& t : threads)
		t.join();
}

