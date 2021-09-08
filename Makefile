SOURCE_DIR := src
SOURCES := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS := $(SOURCES:.c=.o)

# Tools
CC              := gcc
CFLAGS          := -g -Wall -Werror -O0 -Iinclude
OPENSSL_LDFLAGS := -lssl -lcrypto
UUID_LDFLAGS    := -luuid

# Targets
TARGETS := sev-guest
TARGETS += sev-guest-get-report
TARGETS += sev-guest-parse-report
TARGETS += sev-guest-get-cert-chain

TARGETS += sev-host
TARGETS += sev-host-set-cert-chain

# Rules
.PHONY: all clean

all: $(TARGETS)

sev-guest: src/sev-guest.o
	$(CC) $(CFLAGS) -o $@ $^

sev-guest-get-report: src/get-report.o
	$(CC) $(CFLAGS) -o $@ $^ $(OPENSSL_LDFLAGS)

sev-guest-parse-report: src/parse-report.o src/report.o
	$(CC) $(CFLAGS) -o $@ $^ $(OPENSSL_LDFLAGS)

sev-guest-get-cert-chain: src/get-cert-chain.o
	$(CC) $(CFLAGS) -o $@ $^

sev-host: src/sev-host.o
	$(CC) $(CFLAGS) -o $@ $^

sev-host-set-cert-chain: src/set-cert-chain.o src/cert-table.o
	$(CC) $(CFLAGS) -o $@ $^ $(UUID_LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OBJECTS)
