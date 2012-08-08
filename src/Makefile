
CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=-lpcap
SOURCES=main.c util.c
SOURCES+=parser_radiotap.c
SOURCES+=parser_ieee80211.c
SOURCES+=radiotap.c
SOURCES+=generic_classifier.c
SOURCES+=statistics.c
SOURCES+=view_main.c

OBJECTS=$(SOURCES:.c=.o)

LIBS=-lm -lcurses

all: rac

debug: CFLAGS += -DDO_DEBUG=1
debug: rac

debugpkt: CFLAGS += -DDEBUGPKT=1
debugpkt: rac

radiotap.o: radiotap.c radiotap.h radiotap_iter.h
capture.o: capture.c capture.h
main.o: main.c main.h
parser_radiotap.o: parser_radiotap.c parser.h
parser_ieee80211.o: parser_ieee80211.c parser.h
util.o: util.c util.h ieee80211.h
ieee80211_util.o: ieee80211_util.c ieee80211_util.h
generic_classifier.o: generic_classifier.c generic_classifier.h
statistics.o: statistics.c statistics.h
view_main.o: view_main.c view_main.h

rac: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	@${RM} *.o
	@${RM} rac

