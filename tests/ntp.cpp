
#include <cstdio>

#include <IPEndpoint.hpp>
#include <IP.hpp>
#include <NTP.hpp>

#include <ctime>

int main() {
	ip::Init();
	
	std::vector<ip::Endpoint> endpoints;
	endpoints.emplace_back(ip::GetAddress("129.6.15.29", 37));
	endpoints.emplace_back(ip::GetAddress("129.6.15.28", 37));
	endpoints.emplace_back(ip::GetAddress("129.6.15.30", 37));
	endpoints.emplace_back(ip::GetAddress("132.163.97.2", 37));
	endpoints.emplace_back(ip::GetAddress("132.163.96.3", 37));
	
	// ip address from website: 
	// https://tf.nist.gov/tf-cgi/servers.cgi
	int32_t t = ip::udp::NTP({ip::GetAddress("129.6.15.29", 37)});
	printf("\n received time: %i", t);
	printf("\n          time: %i", (int32_t)time(NULL));
	printf("\n");
	
	ip::Deinit();
	return 0;
}

