
#include "Benchmarking.cpp"

#include <GenPK.hpp>
#include <Util.hpp>

TimeMeasures<double, double>
	timeGen,
	timeSign,
	timeVeri,
	timeEncrypt,
	timeDecrypt,
	timeEncode,
	timeDecode;
ValueMeasures<int, int> sizeMeas;

int bits = 4096;
bool realtimeEssentialsOnly = false;

class ThreadData {
public:
	ThreadData() {
		GenerateKeys(key, pubkey, bits);
	}
	
	PKPrivate key;
	PKPublic pubkey;
	char buf[mbedtls::MAX_BYTES];
	char buf2[mbedtls::MAX_BYTES];
};

void Benchmark(ThreadData& data) {
	char *buf = data.buf;
	char *buf2 = data.buf2;
	size_t size, size2;
	
	decltype(timeGen.Start()) t;
	const static size_t messageSize =
		bits>4096 ? 800 :
		bits>2048 ? 400 :
		bits>1024 ? 200 :
		48;

	PKPrivate& key = data.key;
	PKPublic& pubkey = data.pubkey;
	uint32_t err = 0;
	bool b = true;

	if(!realtimeEssentialsOnly) {
		mbedtls::err = 0;
		t = timeGen.Start();
		err=(err<<1) | (b?0:1); b = GenerateKeys(key, pubkey, bits);
		timeGen.End(t);
	}
	
	mbedtls::err = 0;
	size2 = size = mbedtls::MAX_BYTES;
	mbedtls::Random(NULL, buf, mbedtls::MAX_BYTES);
	buf[0] = 0;
	t = timeEncrypt.Start();
	err=(err<<1) | (b?0:1); b = pubkey.Encrypt(buf, messageSize, buf2, &size2);
	timeEncrypt.End(t);
	
	mbedtls::err = 0;
	t = timeDecrypt.Start();
	err=(err<<1) | (b?0:1); b = key.Decrypt(buf2, size2, buf, &size);
	timeDecrypt.End(t);
	
	mbedtls::err = 0;
	size2 = mbedtls::MAX_BYTES;
	t = timeSign.Start();
	err=(err<<1) | (b?0:1); b = key.SignHash(buf, 64, buf2, &size2);
	timeSign.End(t);
	
	mbedtls::err = 0;
	t = timeVeri.Start();
	err=(err<<1) | (b?0:1); b = pubkey.VerifyHash(buf, 64, buf2, size2);
	timeVeri.End(t);
	
	if(!realtimeEssentialsOnly) {
		mbedtls::err = 0;
		t = timeEncode.Start();
		size = mbedtls::MAX_BYTES;
		for(int i=0; i<1000; ++i) {
			err=(err<<1) | (b?0:1); b = pubkey.GetDER((void*)buf, (int*)&size);
		}
		timeEncode.End(t);
		
		sizeMeas.Add(size);
		
		mbedtls::err = 0;
		t = timeDecode.Start();
		for(int i=0; i<1000; ++i) {
			err=(err<<1) | (b?0:1); b = pubkey.Init(buf, size);
		}
		timeDecode.End(t);
	}
}

void Print() {
	gotoxy(0, 0);
	
	printf("\n Using bits: %i", bits);
	printf("\n count: %lli\n", (long long int)timeEncrypt.data.size());
	printf("\n test                   avg         max        stddev");
	
	if(!realtimeEssentialsOnly)  {
		sizeMeas.PrintI("size", 1);
		timeGen.PrintF("timeGen", 1);
		timeEncode.PrintE("timeEncode", 1000);
		timeDecode.PrintE("timeDecode", 1000);
	}
	if(true) {
		timeSign.PrintE("timeSign", 1);
		timeVeri.PrintE("timeVeri", 1);
		timeEncrypt.PrintE("timeEncrypt", 1);
		timeDecrypt.PrintE("timeDecrypt", 1);
	}
	printf("\n");
}

int main(int argc, char **argv) {
	if(argc > 2)
		bits = atoi(argv[2]);
	if(argc > 3) {
		if(strcmp(argv[3], "RealtimeEssentials") == 0) {
			realtimeEssentialsOnly = true;
		}
	}
	BenchmarkMain<ThreadData>(argc, argv, Benchmark, Print);
	return 0;
}
