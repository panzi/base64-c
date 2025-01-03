CC = gcc
CFLAGS = -Wall -std=gnu2x -Werror
BUILD_DIR = build
OBJ = $(BUILD_DIR)/encode.o $(BUILD_DIR)/decode.o $(BUILD_DIR)/util.o
SO_OBJ = $(BUILD_DIR)/so_encode.o $(BUILD_DIR)/so_decode.o $(BUILD_DIR)/so_util.o
BIN_OBJ = $(BUILD_DIR)/main.o $(OBJ)
SO = $(BUILD_DIR)/libbase64.so
LIB = $(BUILD_DIR)/libbase64.a
BIN = $(BUILD_DIR)/base64
DEBUG = ON
AR = ar
PREFIX = /usr/local

ifeq ($(DEBUG),ON)
	CFLAGS += -g
	BUILD_DIR = build/debug
else
	CFLAGS += -O3 -DNDEBUG
	BUILD_DIR = build/release
endif

.PHONY: all so lib clean test install uninstall

all: $(BIN) $(SO) $(LIB)

so: $(SO)

lib: $(LIB)

install: $(BIN) $(SO) $(LIB)
	cp base64.h $(PREFIX)/include
	cp $(BIN) $(PREFIX)/bin
	cp $(SO) $(LIB) $(PREFIX)/lib

uninstall:
	rm -v \
		$(PREFIX)/include/base64.h \
		$(PREFIX)/bin/base64 \
		$(PREFIX)/lib/libbase64.so \
		$(PREFIX)/lib/libbase64.a

test: $(BIN)
	./test.sh $(BIN)

$(BIN): $(BIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

$(SO): $(SO_OBJ)
	$(CC) -shared $(CFLAGS) -o $@ $^

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(BUILD_DIR)/so_%.o: %.c base64.h
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

$(BUILD_DIR)/%.o: %.c base64.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -v $(BIN_OBJ) $(SO_OBJ) $(SO) $(LIB) $(BIN)
