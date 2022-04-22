CC=clang++
COMPILER_FLAGS= -std=c++14
FLAGS=-g -fPIC

PROJ_NAME=dobermann
LIBS=-levent -lpcap

default: all

main.o: src/main.cpp
	$(CC) src/main.cpp -c -o main.o $(COMPILER_FLAGS) $(FLAGS)

logging.o: src/utils/logging.h src/utils/logging.cpp
	$(CC) src/utils/logging.cpp -c -o logging.o $(COMPILER_FLAGS) $(FLAGS)

utils.o: src/utils/utils.h src/utils/utils.cpp
	$(CC) src/utils/utils.cpp -c -o utils.o $(COMPILER_FLAGS) $(FLAGS)

sniffer.o: src/sniffers/sniffer.h src/sniffers/sniffer.cpp
	$(CC) src/sniffers/sniffer.cpp -c -o sniffer.o $(COMPILER_FLAGS) $(FLAGS)

http_sniffer.o: src/sniffers/http_sniffer.h src/sniffers/http_sniffer.cpp
	$(CC) src/sniffers/http_sniffer.cpp -c -o http_sniffer.o $(COMPILER_FLAGS) $(FLAGS)

http_detections.o: src/detections/http_detections.h src/detections/http_detections.cpp
	$(CC) src/detections/http_detections.cpp -c -o http_detections.o $(COMPILER_FLAGS) $(FLAGS)

engine.o: src/engine/engine.h src/engine/engine.cpp
	$(CC) src/engine/engine.cpp -c -o engine.o $(COMPILER_FLAGS) $(FLAGS)

dobermann: main.o logging.o utils.o sniffer.o http_sniffer.o engine.o http_detections.o
	$(CC) main.o logging.o utils.o sniffer.o http_sniffer.o engine.o http_detections.o -o $(PROJ_NAME) $(COMPILER_FLAGS) $(FLAGS) $(LIBS)

test_main.o: tests/test_main.cpp
	$(CC) tests/test_main.cpp -c -o test_main.o $(COMPILER_FLAGS) $(FLAGS)

tests: test_main.o
	$(CC) test_main.o -o test_$(PROJ_NAME) $(COMPILER_FLAGS) $(LIBS)

all: dobermann tests

clean:
	rm dobermann -f
	rm test_dobermann -f
	rm *.o -f

