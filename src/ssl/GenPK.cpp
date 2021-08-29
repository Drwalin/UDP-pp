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

#include "GenPK.hpp"

#define ADD_ARG(_STR) ({ \
	argv[argc] = strstr(argString, _STR); \
	++argc; \
})

#include "../../generate_key.c"
bool GenerateKeys(PKPrivate& key, PKPublic& pubkey, int keyBitsLength) {
	char argString[1024];
	int argc = 0;
	char *argv[256];
	memset(&(argv[0]), 0, sizeof(argv));
	
	snprintf(argString, 1024, "nope type=rsa rsa_keysize=%i filename=dup format=pem", keyBitsLength);
	
	ADD_ARG("nope");
	ADD_ARG("type");
	ADD_ARG("rsa_keysize");
	ADD_ARG("filename");
	ADD_ARG("format");
	
	for(int i=1; i<argc; ++i)
		*(argv[i]-1) = 0;
	
	uint8_t buf[16000];
	size_t len = 16000;
	memset(buf, 0, len);
	
	if(generate_key_main(argc, argv, buf, &len) != 0) {
		printf("\n   Failed generate_key_main()");
		return false;
	}

	buf[len] = 0;
	buf[len+1] = 0;
	if(key.Init(buf, len+1, NULL) == false) {
		printf("\n   Failed key.Init()");
		return false;
	}

	if(key.GetPublic(pubkey) == false) {
		printf("\n   Failed key.GetPublic()");
		return false;
	}

	return true;
}
	
#undef ADD_ARG

