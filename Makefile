SHELL := /bin/bash

PROJECT := SecureXfer
SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
BIN := $(BUILD_DIR)/$(PROJECT)

CC := gcc
CFLAGS := -O2 -Wall -Wextra -I$(INC_DIR) -I$(INC_DIR)/core -I$(INC_DIR)/utils -I$(INC_DIR)/cli -std=c11 -pthread

SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

DEPS := $(OBJS:.o=.d)

.PHONY: all clean distclean directories

all: directories $(BIN)

directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)/core
	@mkdir -p $(BUILD_DIR)/utils
	@mkdir -p $(BUILD_DIR)/cli

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -c $< -o $@

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto -lz

-include $(DEPS)

clean:
	rm -rf $(BUILD_DIR)/*

distclean: clean
	rm -rf $(BUILD_DIR)
