#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>

namespace HTTP{

enum class Method{
    GET, 
    POST,
    PUT,
    DELETE_,   // DELETE is a reserved keyword, so.
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
    ERROR
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

    std::string getHeader(const std::string& name) const;
    bool hasHeader(const std::string& name) const;
    size_t getContentLength() const;
    bool isChunked() const;
    bool isKeepAlive() const;
    std::string getHost() const;
};

class Parser{
private:
    ParseState state;
    std::string buffer;
    Request request;
    size_t bodyBytesRead;
    size_t expectedBodyLength;
    std::string errorMessage;

    // MAX SIZES FOR HEADERS???

    bool parseRequestLine();
    bool parseHeaders();
    bool parseBody();
    Method stringToMethod(const std::string& str);
    std::string trim(const std::string& str);
    std::string toLower(const std::string& str);

public:
    Parser();

    void reset();

    // feed data to the parser, return true if more data is needed
    bool feed(const char* data, size_t len);

    //current state of the parser
    ParseState getState() const {return state;}

    // get the parsed request after state == COMPLETE
    const Request& getRequest() const {return request;}

    // return error message when state == ERROR
    const std::string& getError() const {return errorMessage;}

    //check if the request if fully parsed
    bool isComplete() const {return state == ParseState::COMPLETE;}

    // check for error
    bool hasError() const {return state == ParseState::ERROR;}
};

// forwarded request with proxy headers
std::string buildForwardedRequest(
    const Request& original, 
    const std::string& clientIP,
    bool isTLS
);

// error response
std::string buildErrorResponse(int statusCode, const std::string& message);
}