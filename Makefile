PROJNAME=dobermann

CC=clang++
CFLAGS=-std=c++14 -fPIC -ggdb -O0 -Wall -Wextra -Werror -Winline -MD

LIBS=-levent -lpcap -lcurl

CPP=$(shell find ./src -name "*.cpp")
OBJ=$(patsubst %,obj/%.o,$(basename $(CPP)))

default: all

obj/./src/%.o: src/%.cpp
	@mkdir -p $(@D)
	@echo -e "\033[0;32mCompiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(PROJNAME): $(OBJ)
	@echo -e "\033[0;36mLinking $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -e "\033[0;35mSrc done"

all: $(PROJNAME)
	@echo -e "\033[0;37mAll done"

clean:
	@echo -e "\033[1;33mCleaning up"
	@rm $(PROJNAME) -f
	@rm $(TESTNAME) -f
	@rm $(OBJ) -f
	@rm $(patsubst %.o, %.d, $(OBJ))

-include $(OBJ:.o=.d)

