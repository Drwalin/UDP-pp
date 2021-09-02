/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2021 Marek Zalewski aka Drwalin
 *
 *  This is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef DRWALIN_CERTIFICATE_DATA_HPP
#define DRWALIN_CERTIFICATE_DATA_HPP

#include <PK.hpp>
#include <SHA256.hpp>

#include <cstring>
#include <cinttypes>

class CertData {
public:
	
	inline const static uint8_t MaxCertChainLength = 7;
	
	CertData();
	~CertData();
	
	void SetVersion(uint8_t version);
	void SetExpiryTime(int64_t days);
	bool AddToCertChain(class Cert* cert);
	void SetPublicKey(const PKPublic& pubkey);
	
private:
	
	uint8_t version;
	
	int64_t expiryDays;
	
	int8_t parentingCertChainLength;
	uint8_t certChain[MaxCertChainLength*SHA256::HashBytes];
	
	
};

#endif

