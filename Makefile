# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread

TARGET = main.exe

SRCS = main.cpp

# Build
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) -lws2_32

# Clean
.PHONY: Clean
clean:
	del $(TARGET)