# =========================================================================
# Aviation Lightweight PKI System - Build Configuration
# Platforms: Linux (Default), Windows (MinGW)
# =========================================================================

CC = gcc
CFLAGS = -Wall -Wextra -I./include -D_POSIX_C_SOURCE=200809L -O2
LDFLAGS = -lssl -lcrypto

TARGET_DEMO = sm2_implicit_cert_demo.exe
TARGET_TEST = run_tests.exe

COMMON_OBJ = src/sm2_implicit_cert.o
MAIN_OBJ = src/main.o
TEST_OBJ = src/test_suite.o

.PHONY: all clean clean_linux run test help

all: $(TARGET_DEMO)

# Compile Object Files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link Targets
$(TARGET_DEMO): $(COMMON_OBJ) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_TEST): $(COMMON_OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Commands
run: $(TARGET_DEMO)
	@echo [EXEC] Starting Demo...
	@./$(TARGET_DEMO)

test: $(TARGET_TEST)
	@echo [EXEC] Running Tests...
	@./$(TARGET_TEST)

clean:
	@echo [CLEAN] Removing artifacts (Windows)...
	-@del /Q /S src\*.o 2>NUL
	-@del /Q /S *.o 2>NUL
	-@del /Q /S *.exe 2>NUL

clean_linux:
	@echo [CLEAN] Removing artifacts (Linux)...
	rm -f src/*.o *.o *.exe $(TARGET_DEMO) $(TARGET_TEST)

help:
	@echo Available targets: all, run, test, clean, clean_linux