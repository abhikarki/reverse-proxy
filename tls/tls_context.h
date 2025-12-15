#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <string>
#include <stdexcept>
#include <vector>


namespace TLS{
    class Context{
    private:
        SSL_CTX* ctx;
    
    public:
        Context(): ctx(nullptr){}

        ~Context(){
            if(ctx){
                SSL_CTX_free(ctx);
            }
        }

        static void initLibrary(){
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
        }

        static void cleanupLibrary(){
            EVP_cleanup();
            ERR_free_strings();
        }

        // initializing server context with certificate and key
        bool initServer(const std::string& certFile, const std::string& keyFile){
            // creating TLS sever context (TLS 1.2 and 1.3)
            ctx = SSL_CTX_new(TLS_server_method());
            if(!ctx) return false;

            // minimum TLS version
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

            // loading the certificate in PEM format to SSL context
            if(SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0){
                ERR_print_errors_fp(stderr);       // retrieve and print error from openSSL error stack
                return false;
            }

            // loading private key
            if(SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0){
                ERR_print_errors_fp(stderr);
                return false;
            }

            // verifying that private key matches with the certificate
            if(!SSL_CTX_check_private_key(ctx)){
                fprintf(stderr, "Private key does not match the certificate\n");
                return false;
            }

            // Cipher list for TLS 1.2
            SSL_CTX_set_cipher_list(ctx, 
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384");

            // ciphersuites for TLS 1.3
            SSL_CTX_set_ciphersuites(ctx,
                "TLS_AES_128_GCM_SHA256:"
                "TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256");

            // caching session to reduce the TLS handshake overhead
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
            SSL_CTX_sess_set_cache_size(ctx, 1024);            // cache for upto 1024 clients

            return true;
        }

        // Initializing client context since the proxy is a client for the upstream
        bool initClient(){
            ctx = SSL_CTX_new(TLS_client_method());
            if(!ctx){
                return false;
            }

            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

            // loading certificate for verifying server's identity 
            SSL_CTX_set_default_verify_paths(ctx);

            return true;
        }

        SSL_CTX* get() const {return ctx;}

        /*
        ALPN to reduce additional work later for selecting the application layer protocol.
        takes a list of protocols as strings and creates the compact list of protocols
        wire format is the length prefixed strings, e.g "http/1.1" becomes \x08http/1.1.
        */
        void setALPN(const std::vector<std::string>& protocols){
            std::vector<unsigned char> wire;
            for(const auto& proto : protocols){
                wire.push_back(static_cast<unsigned char>(proto.size()));
                wire.insert(wire.end(), proto.begin(), proto.end());
            }
            SSL_CTX_set_alpn_protos(ctx, wire.data(), static_cast<unsigned>(wire.size()));
        }

        // SNI callback. take two arguments: pointer to our custom function and any extra data.
        void setSNICallback(int (*callback)(SSL*, int*, void*), void* arg){
            // register the function pointer with the OpenSSL context so it calls this automatically during TLS handshake when client sends SNI hostname 
            SSL_CTX_set_tlsext_servername_callback(ctx, callback);
            // store arg within OpenSSL context. arg is automatically passed to callback function when invoked.
            SSL_CTX_set_tlsext_servername_arg(ctx, arg);
        }
    };
}