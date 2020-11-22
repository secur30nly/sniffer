TARGET=sniffer
CC=gcc
CFLAGS=-c -g



all: $(TARGET)

$(TARGET): combineProto.o decoders.o dataHandlers.o main.o modificators.o modifyHandler.o states.o
	$(CC) -o $(TARGET) combineProto.o decoders.o dataHandlers.o main.o modificators.o states.o modifyHandler.o -lpcap
	

combineProto.o: combineProto.c
	$(CC) $(CFLAGS) combineProto.c

decoders.o: decoders.c
	$(CC) $(CFLAGS) decoders.c

dataHandlers.o: dataHandlers.c
	$(CC) $(CFLAGS) dataHandlers.c

state_machine.o: main.c
	$(CC) $(CFLAGS) main.c

modificators.o: modificators.c
	$(CC) $(CFLAGS) modificators.c

modifyHandler.o: modifyHandler.c
	$(CC) $(CFLAGS) modifyHandler.c

states.o: states.c
	$(CC) $(CFLAGS) states.c

clean:
	rm -rf *.o
