CC := g++
CFLAGS := -Wall -Wextra -Ofast -march=native
LDFLAGS := -lm -lcrypto -pthread --static
SRC_DIR := .
OBJ_DIR := obj
BIN_DIR := /usr/local/bin
SRC := $(wildcard $(SRC_DIR)/*.cpp)
OBJ := $(SRC:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
OUT := $(BIN_DIR)/av

$(OUT): $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) $< -c -o $@

.PHONY: clean
clean:
	rm -f $(OUT)
	rm -f $(OBJ)

