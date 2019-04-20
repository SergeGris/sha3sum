
CC=gcc
CFLAGS=-Wall -O2 -pedantic -std=gnu11
SRCDIR=src
LIBDIR=lib
INCLUDEDIR=include
SRC=$(SRCDIR)/*.c $(LIBDIR)/*.c
BIN=sha3sum
PREFIX=/usr/local

all: $(BIN)

sha3sum: $(SRC)
	$(CC) $(SRC) -o $(BIN) $(CFLAGS) -I $(INCLUDEDIR)/

clean:
	rm -f $(BIN)

debug:
	$(CC) $(SRC) -o $(BIN) $(CFLAGS) -I $(INCLUDEDIR)/ -g

install:
	install -m555 $(BIN) $(PREFIX)/bin

uninstall:
	rm $(PREFIX)/bin/$(BIN)

dist: clean
	cd ../; \
	tar zcf SHA3-`date +%Y%m%d%H%M`.txz sha3sum/*

