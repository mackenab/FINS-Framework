CC = gcc
#CFLAGS = -std=gnu99 -Wall -g #-DDEBUG

SRC = ./src
BIN = ./bin


EXECS = wedge_testdaemon

default: all

all:  $(EXECS)

.PHONY: wedge_testdaemon 
wedge_testdaemon:
	$(CC) -lpthread $(SRC)/wedge_testdaemon.c -o $(BIN)/wedge_testdaemon

.PHONY: clean
clean:
	/bin/rm -rf $(BIN)/* core* *~

