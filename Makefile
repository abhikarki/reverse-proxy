-include .env

# Compiler
CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread

# OpenSSL paths (configure for actual paths)
OPENSSL_DIR ?= $(OPENSSL_ROOT)
OPENSSL_INC = -I$(OPENSSL_DIR)/include
OPENSSL_LIB = -L$(OPENSSL_DIR)/lib -lssl -lcrypto

TARGET = main.exe
SRCS = main.cpp rate_limit.cpp load_balancer.cpp http_parser.cpp

# Build
$(TARGET): $(SRCS) proxy.h tls/tls_context.h tls/tls_connection.h
	$(CXX) $(CXXFLAGS) $(OPENSSL_INC) $(SRCS) -o $(TARGET) -lws2_32 $(OPENSSL_LIB)

# Clean
.PHONY: clean
clean:
	del $(TARGET)