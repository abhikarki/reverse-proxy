#include "http_parser.h"
#include <algorithm>
#include <sstream>
#include <cctype>

namespace HTTP
{

    std::string Request::getHeader(const std::string &name) const
    {
        std::string lowerName;
        lowerName.reserve(name.size());
        for (char c : name)
        {
            lowerName += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        // we can put the keys as lower case already
        for (const auto &pair : headers)
        {
            std::string lowerKey;
            lowerKey.reserve(pair.first.size());
            for (char c : pair.first)
            {
                lowerKey += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (lowerKey == lowerName)
            {
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
        // the header could exist and be empty as well
        return headers.find(lowerName) != headers.end();
    }

    size_t Request::getContentLength() const
    {
        std::string value = getHeader("Content-Length");
        if (value.empty())
            return 0;
        try
        {
            return std::stoull(value);
        }
        catch (...)
        {
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

    // constructor
    Parser::Parser() : state(ParseState::REQUEST_LINE), bodyBytesRead(0), expectedBodyLength(0) {}

    void Parser::reset()
    {
        state = ParseState::REQUEST_LINE;
        buffer.clear();
        request = Request();
        bodyBytesRead = 0;
        expectedBodyLength = 0;
        errorMessage.clear();
    }

    std::string Parser::trim(const std::string &str)
    {
        size_t start = 0;
        size_t end = str.size();

        while (start < end && std::isspace(static_cast<unsigned char>(str[start])))
        {
            start++;
        }

        while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1])))
        {
            end--;
        }
        return str.substr(start, end - start);
    }

    std::string Parser::toLower(const std::string &str)
    {
        std::string result;
        result.reserve(str.size());
        for (char c : str)
        {
            result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return result;
    }

    Method Parser::stringToMethod(const std::string &str)
    {
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

    bool Parser::parseRequestLine()
    {
        size_t lineEnd = buffer.find("\r\n");
        if (lineEnd == std::string::npos)
        {
            // need more data
            return true;
        }

        std::string line = buffer.substr(0, lineEnd);
        buffer.erase(0, lineEnd + 2);

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
        return true;
    }

    bool Parser::parseHeaders()
    {
        while (true)
        {
            size_t lineEnd = buffer.find("\r\n");
            if (lineEnd == std::string::npos)
            {
                return true;
            }

            // the headers end with \r\n\r\n, so if the first CRLF is in the beginning, we are done with the headers.
            if (lineEnd == 0)
            {
                buffer.erase(0, 2);

                // check for the body
                expectedBodyLength = request.getContentLength();

                if (request.isChunked())
                {
                    // TO be implemented , right now just treating as no body
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
                    // No body
                    state = ParseState::COMPLETE;
                    return false;
                }
            }

            std::string line = buffer.substr(0, lineEnd);
            buffer.erase(0, lineEnd + 2);

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

            request.headers[name] = value;
        }
    }

    bool Parser::parseBody()
    {
        size_t bytesNeeded = expectedBodyLength - bodyBytesRead;
        size_t bytesAvailable = buffer.size();
        size_t bytesToCopy = std::min(bytesNeeded, bytesAvailable);

        if (bytesToCopy > 0)
        {
            request.body.insert(
                request.body.end(),
                buffer.begin(),
                buffer.begin() + bytesToCopy);
            buffer.erase(0, bytesToCopy);
            bodyBytesRead += bytesToCopy;
        }

        if (bodyBytesRead >= expectedBodyLength)
        {
            state = ParseState::COMPLETE;
            return false;
        }

        // incomplete, we need more data
        return true;
    }

    bool Parser::feed(const char *data, size_t len)
    {
        if (state == ParseState::COMPLETE || state == ParseState::PARSE_ERROR)
        {
            return false;
        }
        buffer.append(data, len);

        constexpr size_t MAX_BUFFER_SIZE = 1024 * 1024;
        if (buffer.size() > MAX_BUFFER_SIZE)
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

            if (needMoreData || state == ParseState::COMPLETE)
            {
                return needMoreData;
            }
        }
    }

    std::string buildForwardedRequest(const Request &original, const std::string &clientIP, bool isTLS)
    {
        std::ostringstream oss;

        oss << original.methodStr << " " << original.uri << " " << original.httpVersion << "\r\n";

        bool hasXForwardedFor = false;
        bool hasXForwardedProto = false;
        bool hasXRealIP = false;

        for (const auto &header : original.headers)
        {
            std::string lowerName = header.first;
            for (char &c : lowerName)
            {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }

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
        std::string statusText;
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
        default:
            statusText = "Error";
            break;
        }

        std::ostringstream body;
        body << "<html><head><title>" << statusCode << " " << statusText << "</title></head>";
        body << "<body><h1>" << statusCode << " " << statusText << "</h1>";
        body << "<p>" << message << "</p></body></html>";

        std::string bodyStr = body.str();

        std::ostringstream response;
        response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
        response << "Content-Type: text/html\r\n";
        response << "Content-Length: " << bodyStr.size() << "\r\n";
        response << "Connection: close\r\n";
        response << "\r\n";
        response << bodyStr;

        return response.str();
    }

}
