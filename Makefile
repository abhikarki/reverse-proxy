# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread

TARGET = main.exe
SRCS = main.cpp rate_limit.cpp

# Build
$(TARGET): $(SRCS) proxy.h
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) -lws2_32

# Clean
.PHONY: clean
clean:
	del $(TARGET)