# DO NOT EDIT -----------------------------------------------------------------
C=/afs/nd.edu/user14/csesoft/new/bin/g++
CFLAGS=-Wall
LD=/afs/nd.edu/user14/csesoft/new/bin/g++
LDFLAGS=
# -----------------------------------------------------------------------------

CFLAGGS +=		# Add any flags for compile
LDFLAGS +=		# Add any flags for compile

all: threadedRE

threadedRE: threadedRE.o hashtable.o
	$(LD) $^ $(LDFLAGE) -o threadedRE

threadedRE.o: threadedRE.cpp
	$(C) $(CFLAGS) -c threadedRE.cpp

hashtable.o: hashtable.cpp hashtable.h
	$(C) $(CFLAGS) -c hashtable.cpp

parse_pcap.o: parse_pcap.c parse_pcap.h
	$(C) $(CFLAGS) -c parse_pcap.c

.PHONY: clean
clean:
	rm -f parse_pcap threadedRE *.o
