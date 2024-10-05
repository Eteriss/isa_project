TARGET = dns_monitor
CXX = g++
CPPFLAGS = -std=c++17 -Wall
LDFLAGS = -lpcap

SRC = main.cpp dns_monitor.cpp arg_parser.cpp section.cpp
OBJ = $(SRC:.cpp=.o)

$(TARGET): $(OBJ)
	$(CXX) $(CPPFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
