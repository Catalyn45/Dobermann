PROJNAME=dobermann

CC=clang++
CFLAGS=-std=c++14 -fPIC -ggdb -O0 -Wall -Wextra -Werror -Winline

LIBS=-levent -lpcap

CPP=$(wildcard src/*.cpp) $(wildcard src/*/*.cpp)
OBJ=$(patsubst %,%.o,$(basename $(CPP)))

default: all

%.o: %.cpp
	@echo -e "\033[0;32mCompiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(PROJNAME): $(OBJ)
	@echo -e "\033[0;36mLinking $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -e "\033[0;35mAll done"

all: $(PROJNAME)

clean:
	@echo -e "\033[1;33mCleaning up"
	@rm $(PROJNAME) -f
	@rm $(OBJ) -f
