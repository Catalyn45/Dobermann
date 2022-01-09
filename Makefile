CC=gcc
COMPILER_FLAGS=-lstdc++

FLAGS=-g
PROJ_NAME=dobermann

default: all

main.o: src/main.cpp
	$(CC) src/main.cpp -c -o main.o $(COMPILER_FLAGS) $(FLAGS)

dobermann: main.o
	$(CC) main.o -o $(PROJ_NAME) $(COMPILER_FLAGS)

test_main.o: tests/test_main.cpp
	$(CC) tests/test_main.cpp -c -o test_main.o $(COMPILER_FLAGS) $(FLAGS)

tests: test_main.o
	$(CC) test_main.o -o test_$(PROJ_NAME) $(COMPILER_FLAGS)

all: dobermann tests

clean:
	rm dobermann
	rm test_dobermann
	rm *.o

