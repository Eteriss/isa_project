TARGET = dns_monitor
CXX = g++
CPPFLAGS = -std=c++11 -Wall
OBJ = dns_monitor.o arg_parser.o

$(TARGET): $(OBJ)
	g++ $(CPPFLAGS) -o $(TARGET) $(OBJ) -lpcap

dns_monitor.o: dns_monitor.cpp dns_monitor.hpp arg_parser.hpp
	g++ $(CPPFLAGS) -c dns_monitor.cpp -o dns_monitor.o

arg_parser.o: arg_parser.cpp arg_parser.hpp
	g++ $(CPPFLAGS) -c arg_parser.cpp -o arg_parser.o

clean:
	rm -rf $(TARGET) $(OBJ)
