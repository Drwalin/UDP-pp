
#include "Benchmarking.cpp"

#include <HMACSHA256.hpp>
#include <AES256.hpp>
#include <Util.hpp>

class ThreadData {
public:

	const static size_t size = 1536;
	uint8_t keyaes[32];
	uint8_t keyhmac[32];
	uint8_t iv[16];
	uint8_t hash[32];
	uint8_t hash2[32];
	uint8_t randomData[size];
	uint8_t encrypted[size];
	uint8_t decrypted[size];
	AES256 aes;
	HMACSHA256 hmac;

	ThreadData() {
		mbedtls::Random(NULL, keyaes, 32);
		mbedtls::Random(NULL, keyhmac, 32);
		mbedtls::Random(NULL, iv, 16);
		mbedtls::Random(NULL, randomData, size);
		aes.Reset(keyaes);
		hmac.Reset(keyhmac);
	}
};

TimeMeasures<double, double>
hmacsha256,
	timeAesEncrypt,
	timeAesDecrypt,
	timeEncrypt,
	timeDecrypt;

void Benchmark(ThreadData& data) {

	auto t = hmacsha256.Start();
	data.hmac.Reset();
	data.hmac.Update(data.randomData, data.size);
	data.hmac.Finish(data.hash);
	hmacsha256.End(t);

	t = timeAesEncrypt.Start();
	data.aes.Encrypt(data.iv, data.randomData, data.encrypted, data.size);
	timeAesEncrypt.End(t);

	t = timeAesDecrypt.Start();
	data.aes.Decrypt(data.iv, data.encrypted, data.decrypted, data.size);
	timeAesDecrypt.End(t);

	t = timeEncrypt.Start();
	data.hmac.Reset();
	data.hmac.Update(data.randomData, data.size);
	data.hmac.Finish(data.hash);
	data.aes.Encrypt(data.iv, data.randomData, data.encrypted, data.size);
	timeEncrypt.End(t);

	t = timeDecrypt.Start();
	data.aes.Decrypt(data.iv, data.encrypted, data.decrypted, data.size);
	data.hmac.Reset();
	data.hmac.Update(data.decrypted, data.size);
	data.hmac.Finish(data.hash2);
	if(memcmp(data.hash, data.hash2, 32) != 0) {
	}
	timeDecrypt.End(t);
}

void Print() {
	gotoxy(0, 0);

	printf("\n count: %lli\n", (long long int)timeEncrypt.data.size());
	printf("\n test                  avg         min        stddev      MB/s");

	hmacsha256.PrintInverseF("hmacsha256", 0.000001*1536);
	timeAesEncrypt.PrintInverseF("timeAesEncrypt", 0.000001*1536);
	timeAesDecrypt.PrintInverseF("timeAesDecrypt", 0.000001*1536);
	printf("\n");
	timeEncrypt.PrintInverseF("timeEncrypt", 0.000001*1536);
	timeDecrypt.PrintInverseF("timeDecrypt", 0.000001*1536);

	printf("\n");
}

int main(int argc, char **argv) {
	BenchmarkMain<ThreadData>(argc, argv, Benchmark, Print);

	return 0;
}

