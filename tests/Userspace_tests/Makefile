CC = gcc
#CFLAGS = -std=gnu99 -Wall -g #-DDEBUG

SRC = ./src
BIN = ./bin


EXECS = clone_dgram_test clone_raw_test clone_stream_test sock_dgram_test sock_raw_test sock_stream_test fork_dgram_test fork_raw_test fork_stream_test pthread_dgram_test pthread_raw_test pthread_stream_test

default: all

all:  $(EXECS)

.PHONY: clone_dgram_test
clone_dgram_test: 
	@$(CC) -DSOCK_MODE=SOCK_DGRAM -lpthread $(SRC)/clone_test.c -o $(BIN)/clone_dgram_test

.PHONY: clone_raw_test
clone_raw_test: 
	@$(CC) -DSOCK_MODE=SOCK_RAW -lpthread $(SRC)/clone_test.c -o $(BIN)/clone_raw_test

.PHONY: clone_stream_test
clone_stream_test:
	@$(CC) -DSOCK_MODE=SOCK_STREAM -lpthread $(SRC)/clone_test.c -o $(BIN)/clone_stream_test

.PHONY: sock_dgram_test
sock_dgram_test: 
	@$(CC) -DSOCK_MODE=SOCK_DGRAM $(SRC)/sock_test.c -o $(BIN)/sock_dgram_test

.PHONY: sock_raw_test
sock_raw_test: 
	@$(CC) -DSOCK_MODE=SOCK_RAW $(SRC)/sock_test.c -o $(BIN)/sock_raw_test

.PHONY: sock_stream_test
sock_stream_test:
	@$(CC) -DSOCK_MODE=SOCK_STREAM $(SRC)/sock_test.c -o $(BIN)/sock_stream_test

.PHONY: fork_dgram_test
fork_dgram_test: 
	@$(CC) -DSOCK_MODE=SOCK_DGRAM -lpthread $(SRC)/fork_test.c -o $(BIN)/fork_dgram_test

.PHONY: fork_raw_test
fork_raw_test: 
	@$(CC) -DSOCK_MODE=SOCK_RAW -lpthread $(SRC)/fork_test.c -o $(BIN)/fork_raw_test

.PHONY: fork_stream_test
fork_stream_test:
	@$(CC) -DSOCK_MODE=SOCK_STREAM -lpthread $(SRC)/fork_test.c -o $(BIN)/fork_stream_test

.PHONY: pthread_dgram_test
pthread_dgram_test: 
	@$(CC) -DSOCK_MODE=SOCK_DGRAM -lpthread $(SRC)/pthread_test.c -o $(BIN)/pthread_dgram_test

.PHONY: pthread_raw_test
pthread_raw_test: 
	@$(CC) -DSOCK_MODE=SOCK_RAW -lpthread $(SRC)/pthread_test.c -o $(BIN)/pthread_raw_test

.PHONY: pthread_stream_test
pthread_stream_test:
	@$(CC) -DSOCK_MODE=SOCK_STREAM -lpthread $(SRC)/pthread_test.c -o $(BIN)/pthread_stream_test


.PHONY: clean
clean:
	/bin/rm -rf $(BIN)/*_test core* *~

