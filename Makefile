
include MakefileSTD/MakefileSTD

CXX=g++
CC=gcc

INCLUDES= \
		  -Isrc/ip \
		  -Isrc

CFLAGS= $(INCLUDES) \
		-pedantic -Wall \
		-ggdb3
#		-O4 -s \

LIBS= -lpthread
ifeq ($(platform),win)
	LIBS += -lws2_32
else
endif

CXXFLAGS=$(CFLAGS) -std=c++17


test: ntp udp udp2


udp: tests/udp.exe 
	./tests/udp.exe

udp2: tests/udp2.exe 
	./tests/udp2.exe

ntp: tests/ntp.exe 
	./tests/ntp.exe

tests: tests/udp2.exe tests/udp.exe tests/ntp.exe



_HEADERS_IP= \
			IP.hpp \
			IPEndpoint.hpp \
			IPPacket.hpp \
			NTP.hpp \
			UDPSocket.hpp \
			OSCheck.hpp
HEADERS_IP=$(addprefix src/ip/, $(_HEADERS_IP))

_OBJS_IP= \
		  IP.o \
		  NTP.o \
		  UDPSocket.o \
		  IPEndpoint.o
OBJS_IP=$(addprefix obj/src/ip/, $(_OBJS_IP))

HEADERS=$(HEADERS_IP)
OBJS=$(OBJS_IP)

.PRECIOUS: $(OBJS)


tests/%.exe: obj/tests/%.o $(HEADERS) $(OBJS)
	$(CXX) -o $@ $(CXXFLAGS) $< $(OBJS) $(LIBS)


#tests/udp.exe: $(HEADERS) obj/tests/udp.o libmbedcrypto.a $(OBJS)
#	$(CXX) -o $@ $(CXXFLAGS) obj/tests/udp.o $(OBJS) $(LIBS)




obj/src/ip/%.o: src/ip/%.cpp $(HEADERS_IP)
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

obj/tests/%.o: tests/%.cpp tests/Benchmarking.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) 

obj/programs/%.o: programs/%.cpp
	$(CXX) -c $< -o $@ $(CXXFLAGS) 


.PHONY: clean
clean:
	$(RM) obj$(S)tests$(S)*.o
	$(RM) obj$(S)programs$(S)*.o
	$(RM) obj$(S)src$(S)ip$(S)*.o
	$(RM) programs$(S)*.exe
	$(RM) tests$(S)*.exe

.PHONY: clean_all
clean_all:
	$(RM) obj$(S)tests$(S)*.o
	$(RM) obj$(S)programs$(S)*.o
	$(RM) obj$(S)src$(S)ip$(S)*.o
	$(RM) programs$(S)*.exe
	$(RM) tests$(S)*.exe
	$(RM) libmbedcrypto.a

