SOURCE_DIR := src
SOURCES := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS := $(SOURCES:.c=.o)

# Tools
CC      := gcc
CFLAGS  := -g -Wall -O0 -Iinclude
LDFLAGS := -lssl -lcrypto

# Targets
TARGETS := sev-guest
TARGETS += sev-guest-get-report
TARGETS += sev-guest-parse-report

TARGETS += sev-host
TARGETS += sev-host-set-cert-chain

# Rules
.PHONY: all clean

all: $(TARGETS)

sev-guest: src/sev-guest.o
	$(CC) $(CFLAGS) -o $@ $^

sev-guest-get-report: src/get-report.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sev-guest-parse-report: src/parse-report.o src/report.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sev-host: src/sev-host.o
	$(CC) $(CFLAGS) -o $@ $^

sev-host-set-cert-chain: src/set-cert-chain.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	$(RM) $(TARGETS) $(OBJECTS)
