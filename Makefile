# Variables
C = g++
CFLAGS = -Wall -std=c++11
LIBS = -lssl -lcrypto
SOURCES = BitDrive.cpp Encrypt.cpp
HEADERS = Encrypt.h
OBJECTS = $(SOURCES:.cpp=.o)
EXEC = bit

# Default target
all: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# To obtain object files
%.o: %.cpp $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)

# Debug target
debug: CFLAGS += -g -DDEBUG
debug: all
