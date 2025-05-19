CC = gcc
CFLAGS = -Wall -pthread -Iinclude
LDFLAGS = -lssl -lcrypto

SRC = src/main.c \
      src/server.c \
      src/client.c \
      src/p2p.c \
      src/encryption.c

OUT = build/chatapp

all:
	mkdir -p build
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

clean:
	rm -f build/chatapp