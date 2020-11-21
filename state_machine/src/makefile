TARGET=sniffer
CC=gcc
CFLAGS=-c -g



all: $(TARGET)

$(TARGET): combineprot.o decoders.o dataHandlers.o state_machine.o modificators.o modify_manage.o states.o
	$(CC) -o $(TARGET) combineprot.o decoders.o dataHandlers.o state_machine.o modificators.o states.o modify_manage.o -lpcap

combineprot.o: combineprot.c
	$(CC) $(CFLAGS) combineprot.c

decoders.o: decoders.c
	$(CC) $(CFLAGS) decoders.c

dataHandlers.o: dataHandlers.c
	$(CC) $(CFLAGS) dataHandlers.c

state_machine.o: state_machine.c
	$(CC) $(CFLAGS) state_machine.c

modificators.o: modificators.c
	$(CC) $(CFLAGS) modificators.c

modify_manage.o: modify_manage.c
	$(CC) $(CFLAGS) modify_manage.c

states.o: states.c
	$(CC) $(CFLAGS) states.c

clean:
	rm -rf *.o
