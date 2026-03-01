CC=gcc
CFLAGS=-std=c11 -O2 -Wall -Wextra -pedantic

all: zadanie1

zadanie1: zadanie1.c
	$(CC) $(CFLAGS) -o zadanie1 zadanie1.c

clean:
	rm -f zadanie1