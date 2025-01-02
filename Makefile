CC = gcc
CFLAGS = -Wall -std=gnu2x -Werror
BUILD_DIR = build
OBJ = $(BUILD_DIR)/main.o $(BUILD_DIR)/encode.o $(BUILD_DIR)/decode.o
BIN = $(BUILD_DIR)/base64
DEBUG = ON

ifeq ($(DEBUG),ON)
	CFLAGS += -g
	BUILD_DIR = build/debug
else
	CFLAGS += -O2 -DNDEBUG
	BUILD_DIR = build/release
endif

.PHONY: all clean test

all: $(BIN)

test: $(BIN)
	./test.sh $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

$(BUILD_DIR)/%.o: %.c base64.h
	$(CC) $(CFLAGS) $< -o $@ -c

clean:
	rm -v $(OBJ) $(BIN)
