TOP_DIR    := $(shell pwd)
TESTS_DIR  := tests
SOURCE_DIR := src
SOURCES    := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS    := $(SOURCES:.c=.o)

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

TARGETS += cert-table-tests

# Rules
.PHONY: all clean cscope

all: $(TARGETS)

sev-guest: $(SOURCE_DIR)/sev-guest.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^

sev-guest-get-report: $(SOURCE_DIR)/get-report.o $(SOURCE_DIR)/cert-table.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^ $(OPENSSL_LDFLAGS) $(UUID_LDFLAGS)

sev-guest-parse-report: $(SOURCE_DIR)/parse-report.o $(SOURCE_DIR)/report.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^

sev-guest-get-cert-chain: $(SOURCE_DIR)/get-cert-chain.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^

sev-host: $(SOURCE_DIR)/sev-host.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^

sev-host-set-cert-chain: $(SOURCE_DIR)/set-cert-chain.o $(SOURCE_DIR)/cert-table.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^ $(UUID_LDFLAGS)

cert-table-tests: $(TESTS_DIR)/cert-table-tests.o $(SOURCE_DIR)/cert-table.o
	$(CC) $(CFLAGS) -DPROG_NAME=$@ -o $@ $^ $(UUID_LDFLAGS)

cscope:
	find $(TOP_DIR) -name "*.[chsS]" -a -type f > cscope.files
	cscope -b -q

clean:
	$(RM) $(TARGETS) $(OBJECTS) cscope.*
