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
TARGETS += sev-guest-export-key

# Rules
.PHONY: all clean

all: $(TARGETS)

sev-guest: src/sev-guest.o
	$(CC) $(CFLAGS) -o $@ $^

sev-guest-get-report: src/get-report.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sev-guest-parse-report: src/parse-report.o src/report.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sev-guest-export-key: src/export-key.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OBJECTS)
