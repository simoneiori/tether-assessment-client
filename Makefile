CC = gcc
LDFLAGS = -pthread
CFLAGS = -pthread
OBJS = client.o json.o
SRCDIR = ./
TARGET = client
PROJECT_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(BUILD_MODE),debug)
	CFLAGS += -g -O0
else ifeq ($(BUILD_MODE),run)
	CFLAGS += -O2
else
    $(error Build mode $(BUILD_MODE) not supported by this Makefile)
endif


all:	client

client:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o:	$(PROJECT_ROOT)%.c
	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -rf $(OBJS) $(TARGET)
