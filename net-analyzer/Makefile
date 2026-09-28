CC       ?= cc
CSTD     := -std=c11
WARN     := -Wall -Wextra -Wpedantic -Werror
CFLAGS   ?= -O2
CFLAGS   += $(CSTD) $(WARN) -pthread
CPPFLAGS += -D_DEFAULT_SOURCE -Iinclude
LDFLAGS  += -pthread

BUILD    := build
BIN      := $(BUILD)/net-analyzer
TEST_BIN := $(BUILD)/test_parser

LIB_SRCS := src/parser.c
APP_SRCS := src/main.c $(LIB_SRCS)

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o)
APP_OBJS := $(APP_SRCS:%.c=$(BUILD)/%.o)

SAN_FLAGS := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
             -fno-sanitize-recover=all

.PHONY: all test sanitize clean

all: $(BIN)

$(BIN): $(APP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(TEST_BIN): $(BUILD)/tests/test_parser.o $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

test: $(TEST_BIN)
	./$(TEST_BIN)

# Parser tests under AddressSanitizer + UBSan, in a separate build tree.
sanitize:
	$(MAKE) BUILD=$(BUILD)/sanitize CFLAGS="$(SAN_FLAGS)" \
	        LDFLAGS="-pthread -fsanitize=address,undefined" test

clean:
	rm -rf $(BUILD)

-include $(wildcard $(BUILD)/src/*.d $(BUILD)/tests/*.d)
