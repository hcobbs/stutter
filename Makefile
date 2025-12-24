# Makefile for Stutter CSPRNG Library
#
# [LLM-ARCH] Generated with human review
#
# Targets:
#   all       - Build static and shared libraries
#   static    - Build static library only
#   shared    - Build shared library only
#   test      - Build and run tests
#   example   - Build example program
#   clean     - Remove build artifacts
#   install   - Install to PREFIX (default: /usr/local)

CC = gcc
AR = ar
RANLIB = ranlib

# Compiler flags
CFLAGS = -Wall -Wextra -std=c89 -pedantic -O2 -fPIC
CFLAGS += -I$(SRCDIR) -I$(INCDIR)

# Security hardening flags
CFLAGS += -fstack-protector-strong
# Note: _FORTIFY_SOURCE requires optimization (-O1 or higher)
CFLAGS += -D_FORTIFY_SOURCE=2

# Debug build: make DEBUG=1
ifdef DEBUG
# Remove optimization-dependent hardening for debug builds
CFLAGS = -Wall -Wextra -std=c89 -pedantic -g -O0 -fPIC -DSTUTTER_DEBUG
CFLAGS += -I$(SRCDIR) -I$(INCDIR)
endif

# RAMPart dependency
RAMPART_DIR ?= ../RAMpart
CFLAGS += -I$(RAMPART_DIR)/h

# Linker flags
LDFLAGS = -lpthread -lcrypto -L$(RAMPART_DIR)/lib -lrampart

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
# macOS: OpenSSL from Homebrew (check both Intel and Apple Silicon paths)
HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /usr/local)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo $(HOMEBREW_PREFIX)/opt/openssl)
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
else
# Linux/BSD: enable RELRO hardening
LDFLAGS += -Wl,-z,relro,-z,now
endif

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
LIBDIR = lib
BINDIR = bin
TESTDIR = tests
EXDIR = examples

# Installation
PREFIX ?= /usr/local

# Source files
SOURCES = \
	$(SRCDIR)/sha256.c \
	$(SRCDIR)/aes256.c \
	$(SRCDIR)/accumulator.c \
	$(SRCDIR)/generator.c \
	$(SRCDIR)/entropy.c \
	$(SRCDIR)/secure_mem.c \
	$(SRCDIR)/stutter.c \
	$(SRCDIR)/platform/posix.c

# Object files
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# Library names
STATIC_LIB = $(LIBDIR)/libstutter.a
SHARED_LIB = $(LIBDIR)/libstutter.so

# Test sources
TEST_SOURCES = \
	$(TESTDIR)/test_main.c \
	$(TESTDIR)/test_sha256.c \
	$(TESTDIR)/test_aes256.c \
	$(TESTDIR)/test_generator.c \
	$(TESTDIR)/test_accumulator.c \
	$(TESTDIR)/test_security.c \
	$(TESTDIR)/test_thread.c

TEST_BIN = $(BINDIR)/test_stutter

# Example
EXAMPLE_BIN = $(BINDIR)/example

# Default target
all: static shared

static: $(STATIC_LIB)

shared: $(SHARED_LIB)

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/platform

$(LIBDIR):
	mkdir -p $(LIBDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/platform/%.o: $(SRCDIR)/platform/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build static library
$(STATIC_LIB): $(OBJECTS) | $(LIBDIR)
	$(AR) rcs $@ $(OBJECTS)
	$(RANLIB) $@
	@echo "Built static library: $@"

# Build shared library
$(SHARED_LIB): $(OBJECTS) | $(LIBDIR)
	$(CC) -shared -o $@ $(OBJECTS) $(LDFLAGS)
	@echo "Built shared library: $@"

# Build and run tests
test: $(TEST_BIN)
	@echo "Running tests..."
	@./$(TEST_BIN)

$(TEST_BIN): $(TEST_SOURCES) $(STATIC_LIB) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) $(TEST_SOURCES) -L$(LIBDIR) -lstutter $(LDFLAGS) -o $@

# Build example
example: $(EXAMPLE_BIN)

$(EXAMPLE_BIN): $(EXDIR)/basic_usage.c $(STATIC_LIB) | $(BINDIR)
	$(CC) $(CFLAGS) $(EXDIR)/basic_usage.c -L$(LIBDIR) -lstutter $(LDFLAGS) -o $@

# Install
install: all
	install -d $(PREFIX)/include
	install -d $(PREFIX)/lib
	install -m 644 $(INCDIR)/stutter.h $(PREFIX)/include/
	install -m 644 $(STATIC_LIB) $(PREFIX)/lib/
	install -m 755 $(SHARED_LIB) $(PREFIX)/lib/
	@echo "Installed to $(PREFIX)"

# Uninstall
uninstall:
	rm -f $(PREFIX)/include/stutter.h
	rm -f $(PREFIX)/lib/libstutter.a
	rm -f $(PREFIX)/lib/libstutter.so

# Clean
clean:
	rm -rf $(OBJDIR) $(LIBDIR) $(BINDIR)
	@echo "Clean complete"

# Phony targets
.PHONY: all static shared test example clean install uninstall

# Dependencies (simplified)
$(OBJDIR)/sha256.o: $(SRCDIR)/sha256.c $(SRCDIR)/stutter_internal.h
$(OBJDIR)/aes256.o: $(SRCDIR)/aes256.c $(SRCDIR)/stutter_internal.h
$(OBJDIR)/accumulator.o: $(SRCDIR)/accumulator.c $(SRCDIR)/stutter_internal.h
$(OBJDIR)/generator.o: $(SRCDIR)/generator.c $(SRCDIR)/stutter_internal.h
$(OBJDIR)/entropy.o: $(SRCDIR)/entropy.c $(SRCDIR)/stutter_internal.h
$(OBJDIR)/secure_mem.o: $(SRCDIR)/secure_mem.c $(SRCDIR)/secure_mem.h $(SRCDIR)/stutter_internal.h
$(OBJDIR)/stutter.o: $(SRCDIR)/stutter.c $(SRCDIR)/stutter_internal.h $(SRCDIR)/secure_mem.h $(INCDIR)/stutter.h
$(OBJDIR)/platform/posix.o: $(SRCDIR)/platform/posix.c $(SRCDIR)/stutter_internal.h
