#ifndef __CM_SSL_INITIALIZER_H__
#define __CM_SSL_INITIALIZER_H__

#include "Poco/SingletonHolder.h"
#include "Poco/StreamCopier.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/InvalidCertificateHandler.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/SSLException.h"
#include "Poco/File.h"
#include <iostream>
#include <string>       // std::string
#include <sstream>      // std::stringstream
#include <fstream>

using namespace std;
extern unsigned char certificate_pem[];
extern unsigned int certificate_pem_len;
extern unsigned char private_certificate_key_pem[];
extern unsigned int private_certificate_key_pem_len;

class poco_ssl_initializar_t;
namespace {
    static Poco::SingletonHolder<poco_ssl_initializar_t> ssl_initializer_singleton;
}
class poco_ssl_initializar_t {
    public:
        static Poco::Net::Context::Ptr get_client_context() {
            ssl_initializer_singleton.get();
            return Poco::Net::SSLManager::instance().defaultClientContext();
        }

        static Poco::Net::Context::Ptr get_server_context() {
            static bool server_context_inited = false;
            ssl_initializer_singleton.get();

            if(false ==  server_context_inited)
            {
                poco_ssl_server_ctxt_initialize();
                server_context_inited = true;
            }
            return Poco::Net::SSLManager::instance().defaultServerContext();
        }

        static Poco::Net::SSLManager& get_ssl_manager() {
            ssl_initializer_singleton.get();
            return Poco::Net::SSLManager::instance();
        }

    private:
        static bool gen_certs(string certFile, string pKeyFile){
            std::stringstream ss_certs;
            std::stringstream ss_certs_key;

            for(uint i = 0; i < private_certificate_key_pem_len; ++i)
            {
                ss_certs_key << private_certificate_key_pem[i];
            }
            //std::cout << ss_certs_key.str() << endl;
            std::ofstream ostr(pKeyFile);
            Poco::StreamCopier::copyStream(ss_certs_key, ostr);

            for(uint i = 0; i < certificate_pem_len; ++i)
            {
                ss_certs << certificate_pem[i];
            }
            //std::cout << ss_certs.str() << endl;
            std::ofstream ostrc(certFile);
            Poco::StreamCopier::copyStream(ss_certs, ostrc);
            return true;
        }
        poco_ssl_initializar_t() {
            Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> ptrHandler = new Poco::Net::AcceptCertificateHandler(false);
            Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "");
            ptrContext->enableSessionCache(true);
            Poco::Net::SSLManager::instance().initializeClient(0, ptrHandler, ptrContext);
        };
        static void poco_ssl_server_ctxt_initialize() {
            ssl_initializer_singleton.get();

#if 1
            const std::string privateKeyFile = "/etc/ssl/private/hcm_server_key.pem";
            const std::string certificateFile = "/etc/ssl/certs/hcm_server.pem";
            const std::string caLocation = "";
            gen_certs(certificateFile, privateKeyFile);
            Poco::File certPath(certificateFile);
            if(!(certPath.exists() && certPath.isFile()))
            {
                cerr<<" Certificates could not be located. Proceeding with non secure mode..." << endl;
                return;
            }
            Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> ptrServerHandler = new Poco::Net::AcceptCertificateHandler(true);
            Poco::Net::Context::Ptr ptrServerContext = new Poco::Net::Context(Poco::Net::Context::SERVER_USE, privateKeyFile, certificateFile, caLocation, Poco::Net::Context::VERIFY_NONE);
#else
            const std::string pKeyFile = "/tmp/hcm_server_key.pem";
            const std::string certsFile = "/tmp/hcm_server.pem";
            const std::string caLocation = "";
            Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> ptrServerHandler = new Poco::Net::AcceptCertificateHandler(true);
            Poco::Net::Context::Ptr ptrServerContext = new Poco::Net::Context(Poco::Net::Context::SERVER_USE, pKeyFile, certsFile, caLocation, Poco::Net::Context::VERIFY_NONE);
#endif
            Poco::Net::SSLManager::instance().initializeServer(0, ptrServerHandler, ptrServerContext);
        };
        ~poco_ssl_initializar_t() {};
        
        friend class Poco::SingletonHolder<poco_ssl_initializar_t>;
};

#endif //__CM_SSL_INITIALIZER_H__
