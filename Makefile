CC := gcc
CFLAGS := -D_POSIX_C_SOURCE=200809L -std=c11 -Wall -Wextra -pedantic -O2
LDFLAGS :=

SRC_DIR := src
TEST_DIR := tests

SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
SRC_OBJECTS := $(patsubst $(SRC_DIR)/%.c, build/%.o, $(SRC_FILES))

TEST_SRC_OBJECTS := $(patsubst $(SRC_DIR)/%.c, build/tests/src_%.o, $(filter-out $(SRC_DIR)/main.c, $(SRC_FILES)))
TEST_TEST_OBJECTS := $(patsubst $(TEST_DIR)/%.c, build/tests/%.o, $(wildcard $(TEST_DIR)/*.c))
TEST_OBJECTS := $(TEST_SRC_OBJECTS) $(TEST_TEST_OBJECTS)

APP_TARGET := quantum_cli
TEST_TARGET := run_tests

.PHONY: all clean test

all: $(APP_TARGET)

build:
	@mkdir -p build build/tests

$(APP_TARGET): build $(SRC_OBJECTS)
	$(CC) $(CFLAGS) $(SRC_OBJECTS) -o $@ $(LDFLAGS)

build/%.o: $(SRC_DIR)/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tests/src_%.o: $(SRC_DIR)/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tests/%.o: $(TEST_DIR)/%.c | build
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(TEST_TARGET): build $(TEST_OBJECTS)
	$(CC) $(CFLAGS) $(TEST_OBJECTS) -o $(TEST_TARGET) $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -rf build $(APP_TARGET) $(TEST_TARGET)
