#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <memory>
#include <cstring>

namespace HTTP
{
    constexpr size_t MAX_REQUEST_SIZE = 2 * 1024 * 1024;
    constexpr size_t BUFFER_SIZE = 64 * 1024;
    constexpr size_t HEADER_BUFFER_SIZE = 8 * 1024;
    constexpr size_t MAX_HEADERS_COUNT = 128;
    constexpr int POLL_TIMEOUT = 5000;

    enum class Method{
        GET,
        POST,
        PUT,
        DELETE_,
        HEAD,
        OPTIONS,
        PATCH,
        CONNECT,
        TRACE,
        UNKNOWN
    };

    enum class ParseState{
        REQUEST_LINE,
        HEADERS,
        BODY,
        COMPLETE,
        PARSE_ERROR
    };

    struct Request{
        Method method;
        std::string methodStr;
        std::string uri;
        std::string path;
        std::string queryString;
        std::string httpVersion;
        std::unordered_map<std::string, std::string> headers;
        std::vector<char> body;

        std::string getHeader(const std::string &name) const;
        bool hasHeader(const std::string &name) const;
        size_t getContentLength() const;
        bool isChunked() const;
        bool isKeepAlive() const;
        std::string getHost() const;
    };

    class BufferManager{
        private:
            std::vector<char> buffer;
            size_t readPos;
            size_t writePos;
            size_t capacity;
        
        public:
            BufferManager(size_t initialSize = BUFFER_SIZE);
            ~BufferManager() = default;

            bool append(const char *data, size_t len);
            std::optional<std::string> extractLine();
            std::string peek(size_t len) const;
            void consume(size_t len);
            size_t available() const {return writePos - readPos;}
            bool isEmpty() const {return readPos == writePos; }
            void reset();
            size_t getCapacity() const {return capacity;}
    };

    class Parser
    {
        private:
            ParseState state;
            BufferManager buffer;
            Request request;
            size_t bodyBytesRead;
            size_t expectedBodyLength;
            std::string errorMessage;
            int connectionFd;

            bool parseRequestLine();
            bool parseHeaders();
            bool parseBody();
            Method stringToMethod(const std::string &str);

            static inline std::string trim(const std::string &str);
            static inline std::string toLower(const std::string &str);
            static inline void toLowerInPlace(std::string &str);
        
        public:
            Parser();
            ~Parser() = default;

            void reset();
            void setConnectionFd(int fd) {connectionFd = fd;}

            bool feed(const char *data, size_t len);

            ParseState getState() const { return state;}
            const Request &getRequest() const {return request;}
            const std::string &getError() const {return errorMessage;}
            bool isComplete() const {return state == ParseState::COMPLETE;}
            bool hasError() const {return state == ParseState::PARSE_ERROR;}

            size_t getPendingBytes() const {return buffer.available();}
    };

    std::string buildForwardedRequest(
        const Request &original,
        const std::string &clientIP,
        bool isTLS
    );

    std::string buildErrorResponse(int statusCode, const std::string &message);

    inline bool isWhitespace(char c){
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    inline bool isLetter(char c){
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

}