PROJNAME=dobermann

CC=clang++
CFLAGS=-std=c++14 -fPIC -ggdb -O0 -Wall -Wextra -Werror -Winline

LIBS=-levent -lpcap -lcurl
TEST_LIBS = -lgtest -lgtest_main

CPP=$(wildcard src/*.cpp) $(wildcard src/*/*.cpp)
TEST_CPP=$(wildcard tests/*.cpp) $(wildcard tests/*/*.cpp)

OBJ=$(patsubst %,%.o,$(basename $(CPP)))
TEST_OBJ=$(filter-out src/main.o,$(patsubst %,%.o,$(basename $(TEST_CPP))) $(OBJ))

default: all

%.o: %.cpp
	@echo -e "\033[0;32mCompiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(PROJNAME): $(OBJ)
	@echo -e "\033[0;36mLinking $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -e "\033[0;35mSrc done"

test: $(TEST_OBJ)
	@echo -e "\033[0;36mLinking $@"
	@$(CC) $(CFLAGS) -o $(PROJNAME)_test $^ $(LIBS) $(TEST_LIBS)
	@echo -e "\033[0;35mTest done"

all: $(PROJNAME) test
	@echo -e "\033[0;35mAll done"

clean:
	@echo -e "\033[1;33mCleaning up"
	@rm $(PROJNAME) -f
	@rm $(OBJ) -f
