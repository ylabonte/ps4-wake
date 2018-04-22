CC=gcc
CFLAGS=-O2 -g -pipe -Wall -std=gnu99
LDFLAGS=-lssl -lcrypto
TARGET=ps4-wake
PREFIX=/usr

all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(TARGET).c sha1.c -o $(TARGET)

install: all
	install -D ps4-wake $(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)

