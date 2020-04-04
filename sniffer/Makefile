TARGET=sniffer
CC=gcc
CFLAGS=-c -Wall -g



all: $(TARGET)

$(TARGET): combineprot.o decoders.o dumptraffic.o main.o modificators.o stdin.o
	$(CC) -o $(TARGET) combineprot.o decoders.o dumptraffic.o main.o modificators.o stdin.o -lpcap

combineprot.o: combineprot.c
	$(CC) $(CFLAGS) combineprot.c

decoders.o: decoders.c
	$(CC) $(CFLAGS) decoders.c

dumptraffic.o: dumptraffic.c
	$(CC) $(CFLAGS) dumptraffic.c

main.o: main.c
	$(CC) $(CFLAGS) main.c

modificators.o: modificators.c
	$(CC) $(CFLAGS) modificators.c

stdin.o: stdin.c
	$(CC) $(CFLAGS) stdin.c

clean:
	rm -rf *.o

