SOURCE_DIR := src
SOURCES := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS := $(SOURCES:.c=.o)

# Tools
CC      := gcc
CFLAGS  := -g -Wall -O0 -Iinclude
LDFLAGS := -lssl -lcrypto

# Targets
TARGETS := sev-guest sev-guest-get-report

# Rules
.PHONY: all clean

all: $(TARGETS)

sev-guest: src/sev-guest.o
	$(CC) $(CFLAGS) -o $@ $^

sev-guest-get-report: src/get-report.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OBJECTS)
