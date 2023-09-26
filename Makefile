# Variables
CXX = g++
CFLAGS = -Wall -std=c++14 -I/usr/local/include -I/Users/marcplatt/libwally-core/include 
LIBS = -lssl -lcrypto -lcurl -lwallycore $(shell pkg-config --libs libbitcoin-system)
SOURCES = BitDrive.cpp Encrypt.cpp Multisig.cpp
HEADERS = Encrypt.h Multisig.h 
OBJECTS = $(SOURCES:.cpp=.o)
EXEC = bit

# Default target
all: $(EXEC)

$(EXEC): $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LIBS)

# To obtain object files
%.o: %.cpp $(HEADERS)
	$(CXX) -c $(CFLAGS) $(shell pkg-config --cflags libbitcoin-system) $< -o $@

# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)

# Debug target
debug: CFLAGS += -g -DDEBUG
debug: all
