# This Makefile can be used with GNU Make or BSD Make

LIB=libfn-dsa-padded-512_clean.a
BUILD_DIR=build
LIB_PATH=$(BUILD_DIR)/$(LIB)

# Source directories
COMMON_SRC_DIR=src/common
FNDSAPADDED512_SRC_DIR=src/fndsapadded512

# Headers from both directories
COMMON_HEADERS=$(wildcard $(COMMON_SRC_DIR)/*.h)
FNDSAPADDED512_HEADERS=$(wildcard $(FNDSAPADDED512_SRC_DIR)/*.h)
HEADERS=$(COMMON_HEADERS) $(FNDSAPADDED512_HEADERS)

# Object files
COMMON_OBJECTS=$(BUILD_DIR)/fips202.o $(BUILD_DIR)/randombytes.o $(BUILD_DIR)/memory_cleanse.o
FNDSAPADDED512_OBJECTS=$(BUILD_DIR)/codec.o $(BUILD_DIR)/common.o $(BUILD_DIR)/fft.o $(BUILD_DIR)/fpr.o $(BUILD_DIR)/keygen.o $(BUILD_DIR)/pqclean.o $(BUILD_DIR)/rng.o $(BUILD_DIR)/sign.o $(BUILD_DIR)/vrfy.o
OBJECTS=$(COMMON_OBJECTS) $(FNDSAPADDED512_OBJECTS)

CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I$(COMMON_SRC_DIR) -I$(FNDSAPADDED512_SRC_DIR) $(EXTRAFLAGS)

all: $(BUILD_DIR) $(LIB_PATH)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Common objects
$(BUILD_DIR)/%.o: $(COMMON_SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ML-DSA-44 objects
$(BUILD_DIR)/%.o: $(FNDSAPADDED512_SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB_PATH): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

# Test targets
$(BUILD_DIR)/test_fndsapadded512: tests/test_fndsapadded512.c $(LIB_PATH)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lfn-dsa-padded-512_clean

test: $(BUILD_DIR)/test_fndsapadded512
	$(BUILD_DIR)/test_fndsapadded512

clean:
	$(RM) -r $(BUILD_DIR)

.PHONY: all test clean
