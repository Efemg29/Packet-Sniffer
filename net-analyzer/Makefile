CC       ?= cc
CSTD     := -std=c11
WARN     := -Wall -Wextra -Wpedantic -Werror
CFLAGS   ?= -O2
CFLAGS   += $(CSTD) $(WARN) -pthread
CPPFLAGS += -D_DEFAULT_SOURCE -Iinclude
LDFLAGS  += -pthread

BUILD    := build
BIN      := $(BUILD)/net-analyzer
TESTS    := test_parser test_ring_buffer
TEST_BINS := $(TESTS:%=$(BUILD)/%)

LIB_SRCS := src/parser.c src/ring_buffer.c
APP_SRCS := src/main.c $(LIB_SRCS)

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o)
APP_OBJS := $(APP_SRCS:%.c=$(BUILD)/%.o)

SAN_FLAGS := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
             -fno-sanitize-recover=all
TSAN_FLAGS := -O1 -g -fsanitize=thread -fno-omit-frame-pointer

.PHONY: all test sanitize tsan clean
.SECONDARY: $(TESTS:%=$(BUILD)/tests/%.o)

all: $(BIN)

$(BIN): $(APP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/test_%: $(BUILD)/tests/test_%.o $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do echo "== $$t"; ./$$t; done

# All unit tests under AddressSanitizer + UBSan, in a separate build tree.
sanitize:
	$(MAKE) BUILD=$(BUILD)/sanitize CFLAGS="$(SAN_FLAGS)" \
	        LDFLAGS="-pthread -fsanitize=address,undefined" test

# Ring buffer tests (incl. the producer/consumer stress test) under TSan.
tsan:
	$(MAKE) BUILD=$(BUILD)/tsan CFLAGS="$(TSAN_FLAGS)" \
	        LDFLAGS="-pthread -fsanitize=thread" $(BUILD)/tsan/test_ring_buffer
	RB_STRESS_ITERS=200000 ./$(BUILD)/tsan/test_ring_buffer

clean:
	rm -rf $(BUILD)

-include $(wildcard $(BUILD)/src/*.d $(BUILD)/tests/*.d)
