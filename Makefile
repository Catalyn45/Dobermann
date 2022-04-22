CC=clang++
COMPILER_FLAGS= -std=c++14
FLAGS=-g

PROJ_NAME=dobermann
LIBS=-levent -lpcap

default: all

main.o: src/main.cpp
	$(CC) src/main.cpp -c -o main.o $(COMPILER_FLAGS) $(FLAGS)

logging.o: src/utils/logging.h src/utils/logging.cpp
	$(CC) src/utils/logging.cpp -c -o logging.o $(COMPILER_FLAGS) $(FLAGS)

utils.o: src/utils/utils.h src/utils/utils.cpp
	$(CC) src/utils/utils.cpp -c -o utils.o $(COMPILER_FLAGS) $(FLAGS)

sniffer.o: src/engine/sniffer.h src/engine/sniffer.cpp
	$(CC) src/engine/sniffer.cpp -c -o sniffer.o $(COMPILER_FLAGS) $(FLAGS)

http_sniffer.o: src/engine/http_sniffer.h src/engine/http_sniffer.cpp
	$(CC) src/engine/http_sniffer.cpp -c -o http_sniffer.o $(COMPILER_FLAGS) $(FLAGS)

engine.o: src/engine/engine.h src/engine/engine.cpp
	$(CC) src/engine/engine.cpp -c -o engine.o $(COMPILER_FLAGS) $(FLAGS)

dobermann: main.o logging.o utils.o sniffer.o http_sniffer.o engine.o
	$(CC) main.o logging.o utils.o sniffer.o http_sniffer.o engine.o -o $(PROJ_NAME) $(COMPILER_FLAGS) $(LIBS)

test_main.o: tests/test_main.cpp
	$(CC) tests/test_main.cpp -c -o test_main.o $(COMPILER_FLAGS) $(FLAGS)

tests: test_main.o
	$(CC) test_main.o -o test_$(PROJ_NAME) $(COMPILER_FLAGS) $(LIBS)

all: dobermann tests

clean:
	rm dobermann -f
	rm test_dobermann -f
	rm *.o -f

