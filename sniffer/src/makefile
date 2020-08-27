TARGET=sniffer
CC=gcc
CFLAGS=-c -g



all: $(TARGET)

$(TARGET): combineprot.o decoders.o dumptraffic.o main.o modificators.o modify_manage.o
	$(CC) -o $(TARGET) combineprot.o decoders.o dumptraffic.o main.o modificators.o modify_manage.o -lpcap

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

modify_manage.o: modify_manage.c
	$(CC) $(CFLAGS) modify_manage.c

clean:
	rm -rf *.o

