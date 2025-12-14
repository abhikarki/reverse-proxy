#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string>
#include <vector>

namespace TLS{

enum class State{
    HANDSHAKE_READ,
    HANDSHAKE_WRITE,
    ESTABLISHED,
    SHUTDOWN,
    S_ERROR
};

enum class IOResult{
    SUCCESS,
    WANT_READ,      // Need more data from network
    WANT_WRITE,     // Need to send data to network
    CLOSED,
    IO_ERROR
};

class Connection{
private:
    SSL* ssl;
    BIO* rbio;          // buffer for network data
    BIO* wbio;          // buffer for encrypted data
    State state;
    std::string sni;

public:
    Connection(SSL_CTX* ctx, bool isServer = true) : state(State::HANDSHAKE_READ){
        ssl = SSL_new(ctx);

        // allocating buffer for I/O
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());

        // set to non blocking mode
        BIO_set_nbio(rbio, 1);
        BIO_set_nbio(wbio, 1);

        // associate to ssl connection
        SSL_set_bio(ssl, rbio, wbio);

        if(isServer)  SSL_set_accept_state(ssl);     // prepare to accept clientHello
        else SSL_set_connect_state(ssl);             // prepare the client to send clientHello to initiate handshake

    }

    ~Connection(){
        if(ssl){
            SSL_free(ssl);       // this also frees the BIOs
        }
    }

    // donot allow copying
    // Note this is declaration specifier for compiler and not assignment
    Connection(const Connection&) = delete;                    // cannot create new Connection object from existing one e.g. Connection A = B 
    Connection& operator = (const Connection&) = delete;       // cannot assign exising object to another

    // Move constructor using move semantics
    Connection(Connection&& other) noexcept : ssl(other.ssl), rbio(other.rbio), wbio(other.wbio), state(other.state), sni(std::move(other.sni)){
        other.ssl = nullptr;
        other.rbio = nullptr;
        other.wbio = nullptr;
    }

    State getState() const {return state;}
    const std::string& getSNI() const {return sni;}

    // feeding encrypted data received from network into OpenSSL
    void feedNetworkData(const char* data, size_t len){
        BIO_write(rbio, data, static_cast<int>(len));
    }

    // get encrypted data to send to network
    size_t getNetworkData(char* buffer, size_t maxLen){
        int pending = BIO_ctrl_pending(wbio);
        if(pending <= 0) return 0;           //nothing to send

        int toRead = (pending < static_cast<int>(maxLen)) ? pending : static_cast<int>(maxLen);
        int bytesRead = BIO_read(wbio, buffer, toRead);
        return (bytesRead > 0) ? static_cast<size_t>(bytesRead) : 0;
    }

    // check if there is data to send
    bool hasNetworkDataPending() const{
        return BIO_ctrl_pending(wbio) > 0;
    }

    // perform the TLS handshake
    IOResult doHandshake(){
        if(state == State::ESTABLISHED){
            return IOResult::SUCCESS;
        }

        // the function works as a state machine executing next logical step in TLS protocol
        int result = SSL_do_handshake(ssl);

        if(result == 1){
            // handshake completed.
            state = State::ESTABLISHED;

            // extracting SNI 
            const char* serverName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
            if(serverName){
                sni = serverName;
            }

            return IOResult::SUCCESS;
        }

        int err = SSL_get_error(ssl, result);
        switch(err){
            case SSL_ERROR_WANT_READ:             // needs more data from network
                state = State::HANDSHAKE_READ;
                return IOResult::WANT_READ;
            case SSL_ERROR_WANT_WRITE:            // has data to send to network but buffer is full
                state = State::HANDSHAKE_WRITE;
                return IOResult::WANT_WRITE;
            
            default:
                state = State::S_ERROR;
                ERR_print_errors_fp(stderr);
                return IOResult::IO_ERROR;
        }
    }

    // to get decrypted data
    IOResult read(char* buffer, size_t maxLen, size_t& bytesRead){
        bytesRead = 0;

        if(state != State::ESTABLISHED){
            return IOResult::IO_ERROR;
        }

        int result = SSL_read(ssl, buffer, static_cast<int>(maxLen));

        if(result > 0){
            bytesRead = static_cast<size_t>(result);
            return IOResult::SUCCESS;
        }

        int err = SSL_get_error(ssl, result);
        switch(err){
            case SSL_ERROR_WANT_READ:
                return IOResult::WANT_READ;
            case SSL_ERROR_WANT_WRITE:
                return IOResult::WANT_WRITE;
            case SSL_ERROR_ZERO_RETURN:
                state = State::SHUTDOWN;
                return IOResult::CLOSED;
            
            default:
                state = State::S_ERROR;
                return IOResult::IO_ERROR;
        }
    }

    // to write data by encrypting
    IOResult write(const char* data, size_t len, size_t& bytesWritten){
        bytesWritten = 0;
        if(state != State::ESTABLISHED){
            return IOResult::IO_ERROR;
        }

        int result = SSL_write(ssl, data, static_cast<int>(len));

        if(result > 0){
            bytesWritten = static_cast<size_t>(result);
            return IOResult::SUCCESS;
        }

        int err = SSL_get_error(ssl, result);
        switch(err){
            case SSL_ERROR_WANT_READ:
                return IOResult::WANT_READ;

            case SSL_ERROR_WANT_WRITE:
                return IOResult::WANT_WRITE;
            
            default:
                state = State::S_ERROR;
                return IOResult::IO_ERROR;
        }
    }

    // TLS shutdown
    IOResult shutdown(){
        // to close the connection by sending close_notify
        int result = SSL_shutdown(ssl);

        // shutdown complete.
        if(result == 1){
            return IOResult::CLOSED;
        }

        // if it return 0, this means the first part of shutdown(sending our close_notify was successful) 
        // the second part(receiving peer's close_notify) is not yet completed.
        if(result == 0){
            state = State::SHUTDOWN;
            return IOResult::WANT_WRITE;
        }

        // Note:: in the following condition also, we return IOResult::WANT_WRITE, but it doesnot 
        // cause conflict because in both situation we call this method again and it would advance the TLS state machine
        int err = SSL_get_error(ssl, result);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
            state = State::SHUTDOWN;
            return (err == SSL_ERROR_WANT_READ) ? IOResult::WANT_READ : IOResult::WANT_WRITE;
        }

        return IOResult::IO_ERROR;
    }

    // to get the application protocol negotiated during the TLS handshake
    std::string getALPNProtocol() const{
        const unsigned char* proto = nullptr;
        unsigned int protoLen = 0;

        // get the negotiated protocol
        SSL_get0_alpn_selected(ssl, &proto, &protoLen);
        if(proto && protoLen > 0){
            return std::string(reinterpret_cast<const char*>(proto), protoLen);
        }
        return "";
    }

    // get the peer certificate info
    std::string getPeerCertSubject() const{
        X509* cert = SSL_get_peer_certificate(ssl);

        if(!cert) return "";

        // subject field in the X509* is the owner identity
        char subject[256];
        // serialize into single line human readable format
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        X509_free(cert);
        return subject;
    }

    // get the negotiated verion of TLS.
    const char* getVersion() const{
        return SSL_get_version(ssl);
    }

    // get the cipher suite name negotiated, specifying protocols for key exchange, authentication, bulk encryption, and message authentication 
    const char* getCipher() const{
        return SSL_get_cipher_name(ssl);
    }
};
}