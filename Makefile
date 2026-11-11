CLANG   ?= clang
CC      ?= gcc
ARCH    := $(shell uname -m)

BPF_CFLAGS := -O2 -g -Wall -target bpf -mcpu=v3 -Iinclude -I/usr/include/$(ARCH)-linux-gnu
CFLAGS     := -O2 -g -Wall -Iinclude
LDLIBS     := -lbpf

HEADERS := $(wildcard include/*.h)

.PHONY: all clean

all: xdp_filter.o ctl detector

xdp_filter.o: src/xdp_filter.c $(HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ctl: src/ctl.c src/maps.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ src/ctl.c src/maps.c $(LDLIBS)

detector: src/detector.c src/src_table.c src/maps.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ src/detector.c src/src_table.c src/maps.c $(LDLIBS)

clean:
	rm -f xdp_filter.o ctl detector