
#include <cstdio>

#include <crypto/ECDH.hpp>
#include <crypto/Random.cpp>

int main() {
	std::vector<uint8_t> srv_pub, cli_pub, srv_shared, cli_shared;
	srv_pub.resize(1000);
	cli_pub.resize(1000);
	srv_shared.resize(1024);
	cli_shared.resize(1024);
	
	crypto::ECDH srv, cli;
	
	srv.GenerateKeyPair();
	cli.GenerateKeyPair();
	
	srv_pub.resize(srv.GetPublicKeySize());
	srv.GetPublicKey(srv_pub.data());
	
	cli_pub.resize(cli.GetPublicKeySize());
	cli.GetPublicKey(cli_pub.data());
	
	size_t srv_s = srv.DerieveSharedSecret(cli_pub.data(), cli_pub.size(), srv_shared.data());
	srv_shared.resize(srv_s);
	size_t cli_s = cli.DerieveSharedSecret(srv_pub.data(), srv_pub.size(), cli_shared.data());
	cli_shared.resize(cli_s);
	
	int equal = (srv_s==cli_s) && (memcmp(srv_shared.data(), cli_shared.data(), srv_s)==0);
	
	printf(" srv_key_size = %lu\n", srv_pub.size());
	printf(" cli_key_size = %lu\n", cli_pub.size());
	
	printf(" derived keys size: %lu\n", srv_s);
	
	return 0;
}

