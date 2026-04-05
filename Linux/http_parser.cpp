#include "http_parser.h"
#include <algorithm>
#include <sstream>
#include <cctype>
#include <cstring>
#include <unistd.h>
#include <stdexcept>
#include <stdio.h>
#include <iostream>


namespace HTTP{
    BufferManager::BufferManager(size_t initialSize) : readPos(0), writePos(0), capacity(initialSize) {
        buffer.resize(capacity);
    }

    bool BufferManager::append(const char *data, size_t len){
        if(!data || len == 0){
            return true;
        }

        size_t requiredSpace = writePos + len;
        
        if(requiredSpace > capacity){
            if(readPos > 0){
                size_t validData = writePos - readPos;
                std::memmove(buffer.data(), buffer.data() + readPos, validData);
                readPos = 0;
                writePos = validData;
            }

            if(writePos + len > capacity){
                while(capacity < writePos + len){
                    capacity *= 2;
                    if(capacity > MAX_REQUEST_SIZE){
                        capacity = MAX_REQUEST_SIZE;
                        break;
                    }
                }

                if(writePos + len > capacity) return false;

                buffer.resize(capacity);
            }
        }

        std::memcpy(buffer.data() + writePos, data, len);
        writePos += len;
        return true;
    }

    std::optional<std::string> BufferManager::extractLine()
    {
        const char *start = buffer.data() + readPos;
        const char *end = start;
        size_t available = writePos - readPos;

        // Find \r\n
        for (size_t i = 0; i < available - 1; ++i)
        {
            if (start[i] == '\r' && start[i + 1] == '\n')
            {
                std::string line(start, end + i);
                readPos += i + 2;
                return line;
            }
        }

        return std::nullopt; // No \r\n found
    }

    // peek and consume is needed for body because the body could have \r\n as part of its data and extractLine maynot be
    // used in such condition
    std::string BufferManager::peek(size_t len) const{
        size_t available = writePos - readPos;
        size_t toPeek = std::min(len, available);
        return std::string(buffer.data() + readPos, toPeek);
    }

    void BufferManager::consume(size_t len){
        size_t available = writePos - readPos;
        readPos += std::min(len, available);
    }

    void BufferManager::reset(){
        readPos = 0;
        writePos = 0;
    }


    std::string Request::getHeader(const std::string &name) const{
        std::string lowerName;
        lowerName.reserve(name.size());
        for(char c : name){
            lowerName += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        for(const auto &pair : headers){
            std::string lowerKey;
            lowerKey.reserve(pair.first.size());
            for(char c : pair.first){
                lowerKey += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if(lowerKey == lowerName){
                return pair.second;
            }
        }
        return "";
    }

    bool Request::hasHeader(const std::string &name) const
    {
        std::string lowerName;
        lowerName.reserve(name.size());
        for (char c : name)
        {
            lowerName += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return headers.find(lowerName) != headers.end();
    }

    size_t Request::getContentLength() const {
        std::string value = getHeader("Content-Length");
        if(value.empty()){
            return 0;
        }
        try{
            return std::stoull(value);
        }
        catch(...){
            return 0;
        }
    }

    bool Request::isChunked() const
    {
        std::string te = getHeader("Transfer-Encoding");
        std::string lowerName;
        for (char c : te)
        {
            lowerName += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return lowerName.find("chunked") != std::string::npos;
    }

    bool Request::isKeepAlive() const
    {
        std::string connection = getHeader("Connection");
        std::string lower;
        for (char c : connection)
        {
            lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        // HTTP/1.1 default is keep-alive
        if (httpVersion == "HTTP/1.1")
        {
            return lower != "close";
        }

        // HTTP/1.0 default is close
        return lower == "keep-alive";
    }

    std::string Request::getHost() const
    {
        return getHeader("Host");
    }

    Parser::Parser()
        : state(ParseState::REQUEST_LINE),
          buffer(BUFFER_SIZE),
          bodyBytesRead(0),
          expectedBodyLength(0),
          connectionFd(-1)
    {
    }

    void Parser::reset(){
        state = ParseState::REQUEST_LINE;
        buffer.reset();
        request = Request();
        bodyBytesRead = 0;
        expectedBodyLength = 0;
        errorMessage.clear();
    }

    inline std::string Parser::trim(const std::string &str){
        size_t start = 0, end = str.size();
        
        while(start < end && isWhitespace(str[start])) start++;

        while(end > start && isWhitespace(str[end - 1])) end--;

        return str.substr(start, end - start);
    }

    inline std::string Parser::toLower(const std::string &str){
        std::string result;
        result.reserve(str.size());

        for(char c : str){
            result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return result;
    }


    inline void Parser::toLowerInPlace(std::string &str){
        for(char &c : str){
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }

    Method Parser::stringToMethod(const std::string &str){
        if (str == "GET")
            return Method::GET;
        if (str == "POST")
            return Method::POST;
        if (str == "PUT")
            return Method::PUT;
        if (str == "DELETE")
            return Method::DELETE_;
        if (str == "HEAD")
            return Method::HEAD;
        if (str == "OPTIONS")
            return Method::OPTIONS;
        if (str == "PATCH")
            return Method::PATCH;
        if (str == "CONNECT")
            return Method::CONNECT;
        if (str == "TRACE")
            return Method::TRACE;
        return Method::UNKNOWN;
    }

    bool Parser::parseRequestLine(){
        auto lineOpt = buffer.extractLine();
        if(!lineOpt.has_value()){
            return true;
        }

        std::string line = lineOpt.value();
        if(!line.empty() && line.back() == '\r'){
            line.pop_back();
        }

        size_t firstSpace = line.find(' ');
        if (firstSpace == std::string::npos)
        {
            state = ParseState::PARSE_ERROR;
            errorMessage = "Invalid request line: missing method";
            return false;
        }

        size_t secondSpace = line.find(' ', firstSpace + 1);
        if (secondSpace == std::string::npos)
        {
            state = ParseState::PARSE_ERROR;
            errorMessage = "Invalid request line: missing URI";
            return false;
        }

        request.methodStr = line.substr(0, firstSpace);
        request.method = stringToMethod(request.methodStr);
        request.uri = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        request.httpVersion = line.substr(secondSpace + 1);

        size_t queryStart = request.uri.find('?');
        if (queryStart != std::string::npos)
        {
            request.path = request.uri.substr(0, queryStart);
            request.queryString = request.uri.substr(queryStart + 1);
        }
        else
        {
            request.path = request.uri;
            request.queryString = "";
        }

        if (request.httpVersion != "HTTP/1.0" && request.httpVersion != "HTTP/1.1")
        {
            state = ParseState::PARSE_ERROR;
            errorMessage = "Unsupported HTTP version: " + request.httpVersion;
            return false;
        }

        state = ParseState::HEADERS;
        return false;
    }

    bool Parser::parseHeaders()
    {
        while (buffer.available() > 0)
        {
            auto lineOpt = buffer.extractLine();
            if (!lineOpt.has_value())
            {
                return true;   // need more data, no \r\n found
            }

            std::string line = lineOpt.value();

            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            if (line.empty())
            {
                expectedBodyLength = request.getContentLength();

                if (request.isChunked())
                {
                    // Chunked encoding - treat as complete for now
                    state = ParseState::COMPLETE;
                    return false;
                }
                else if (expectedBodyLength > 0)
                {
                    state = ParseState::BODY;
                    request.body.reserve(expectedBodyLength);
                    return true;
                }
                else
                {
                    state = ParseState::COMPLETE;
                    return false;
                }
            }

            size_t colonPos = line.find(':');
            if (colonPos == std::string::npos)
            {
                state = ParseState::PARSE_ERROR;
                errorMessage = "Invalid header line: missing colon";
                return false;
            }

            std::string name = trim(line.substr(0, colonPos));
            std::string value = trim(line.substr(colonPos + 1));

            if (name.empty())
            {
                state = ParseState::PARSE_ERROR;
                errorMessage = "Invalid header: empty name";
                return false;
            }

            if (request.headers.size() >= MAX_HEADERS_COUNT)
            {
                state = ParseState::PARSE_ERROR;
                errorMessage = "Too many headers";
                return false;
            }

            request.headers[name] = value;
        }

        return true; // Need more data
    }

    bool Parser::parseBody()
    {
        size_t bytesNeeded = expectedBodyLength - bodyBytesRead;
        size_t bytesAvailable = buffer.available();
        size_t bytesToCopy = std::min(bytesNeeded, bytesAvailable);

        if (bytesToCopy > 0)
        {
            std::string data = buffer.peek(bytesToCopy);
            request.body.insert(request.body.end(), data.begin(), data.end());
            buffer.consume(bytesToCopy);
            bodyBytesRead += bytesToCopy;
        }

        if (bodyBytesRead >= expectedBodyLength)
        {
            state = ParseState::COMPLETE;
            return false;
        }

        return true; // Need more data
    }

    bool Parser::feed(const char *data, size_t len)
    {
        if (state == ParseState::COMPLETE || state == ParseState::PARSE_ERROR)
        {
            return false;
        }

        if (!buffer.append(data, len))
        {
            state = ParseState::PARSE_ERROR;
            errorMessage = "Request too large";
            return false;
        }

        while (true)
        {
            bool needMoreData = false;

            switch (state)
            {
            case ParseState::REQUEST_LINE:
                needMoreData = parseRequestLine();
                break;
            case ParseState::HEADERS:
                needMoreData = parseHeaders();
                break;
            case ParseState::BODY:
                needMoreData = parseBody();
                break;
            case ParseState::COMPLETE:
            case ParseState::PARSE_ERROR:
                return false;
            }

            if (needMoreData || state == ParseState::COMPLETE || state == ParseState::PARSE_ERROR)
            {
                return needMoreData;
            }
        }
    }

    // ==================== Helper Functions ====================

    std::string buildForwardedRequest(const Request &original, const std::string &clientIP, bool isTLS)
    {
        std::ostringstream oss;

        oss << original.methodStr << " " << original.uri << " " << original.httpVersion << "\r\n";

        bool hasXForwardedFor = false;
        bool hasXForwardedProto = false;
        bool hasXRealIP = false;

        for (const auto &header : original.headers)
        {
            std::string lowerName = HTTP::toLower(header.first);

            if (lowerName == "x-forwarded-for")
            {
                oss << header.first << ": " << header.second << ", " << clientIP << "\r\n";
                hasXForwardedFor = true;
            }
            else if (lowerName == "x-forwarded-proto")
            {
                hasXForwardedProto = true;
                oss << header.first << ": " << header.second << "\r\n";
            }
            else if (lowerName == "x-real-ip")
            {
                hasXRealIP = true;
                oss << header.first << ": " << header.second << "\r\n";
            }
            else if (lowerName == "connection")
            {
                oss << header.first << ": " << header.second << "\r\n";
            }
            else
            {
                oss << header.first << ": " << header.second << "\r\n";
            }
        }

        if (!hasXForwardedFor)
        {
            oss << "X-Forwarded-For: " << clientIP << "\r\n";
        }
        if (!hasXForwardedProto)
        {
            oss << "X-Forwarded-Proto: " << (isTLS ? "https" : "http") << "\r\n";
        }
        if (!hasXRealIP)
        {
            oss << "X-Real-IP: " << clientIP << "\r\n";
        }

        return oss.str();
    }

    std::string buildErrorResponse(int statusCode, const std::string &message)
    {
        const char *statusText = "Error";
        
        switch (statusCode)
        {
        case 400:
            statusText = "Bad Request";
            break;
        case 404:
            statusText = "Not Found";
            break;
        case 500:
            statusText = "Internal Server Error";
            break;
        case 502:
            statusText = "Bad Gateway";
            break;
        case 503:
            statusText = "Service Unavailable";
            break;
        case 504:
            statusText = "Gateway Timeout";
            break;
        }

        std::ostringstream body;
        body << "<html><head><title>" << statusCode << " " << statusText
             << "</title></head><body><h1>" << statusCode << " " << statusText
             << "</h1><p>" << message << "</p></body></html>";

        std::string bodyStr = body.str();

        std::ostringstream response;
        response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n"
                 << "Content-Type: text/html\r\n"
                 << "Content-Length: " << bodyStr.size() << "\r\n"
                 << "Connection: close\r\n"
                 << "\r\n"
                 << bodyStr;

        return response.str();
    }

}