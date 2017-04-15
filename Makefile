CC = gcc
CFLAGS += -g -Wall -pedantic -std=c99
LDLIBS += -lssl -lcrypto

all: client

client: main.c
	$(CC) $^ $(CLAGS) $(LDLIBS) -o $@

clean:
	-rm client main.o
