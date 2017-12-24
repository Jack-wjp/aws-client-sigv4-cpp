#ifndef AWS_CLIENT_H
#define AWS_CLIENT_H

#include <iostream>
#include <sstream> 
#include <cstring>
#include <cassert>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <map>
#include <vector>
#include <algorithm>
#include "openssl/sha.h"
#include "openssl/hmac.h"
#include "json/json.h"
#include "awssigv4.h"

#include "Poco/URI.h"
#include "Poco/UUIDGenerator.h"
#include "Poco/Net/DNS.h"
#include "Poco/Net/HostEntry.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/ICMPClient.h"
#include <Poco/StreamCopier.h>
#include "Poco/Exception.h"
#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/InvalidCertificateHandler.h"
#include "Poco/Net/Context.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/SSLException.h"
#include "Poco/SingletonHolder.h"

#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/AutoPtr.h"
#include "Poco/SAX/InputSource.h"
#include "Poco/DOM/ElementsByTagNameList.h"

#include "Poco/JSON/Parser.h"
#include "Poco/JSON/ParseHandler.h"
#include "Poco/JSON/JSONException.h"
#include "Poco/JSON/Stringifier.h"
#include "Poco/JSON/Object.h"
#include "Poco/Dynamic/Var.h"

#include "Poco/Environment.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Stopwatch.h"

using Poco::JSON::ParseHandler;
using Poco::JSON::Stringifier;
using Poco::JSON::Object;
using Poco::JSON::Parser;
using Poco::Dynamic::Var;
using Poco::DynamicStruct;

using namespace Poco;
using namespace XML;
using namespace Net;
using namespace std;

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

        static Poco::Net::SSLManager& get_ssl_manager() {
            ssl_initializer_singleton.get();
            return Poco::Net::SSLManager::instance();
        }

    private:
        poco_ssl_initializar_t() {
            Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> ptrHandler = new Poco::Net::AcceptCertificateHandler(false);
            Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(Poco::Net::Context::CLIENT_USE, "");
            Poco::Net::SSLManager::instance().initializeClient(0, ptrHandler, ptrContext);
        };
        ~poco_ssl_initializar_t() {};
        
        friend class Poco::SingletonHolder<poco_ssl_initializar_t>;
};

class poco_https_session_t : public Poco::Net::HTTPSClientSession {
    public:
        poco_https_session_t (const std::string &host, Poco::UInt16 port) : 
            HTTPSClientSession(host, port, poco_ssl_initializar_t::get_client_context()) {
            };
        virtual ~poco_https_session_t () {};
};

class poco_http_session_t : public Poco::Net::HTTPClientSession {
    public:
        poco_http_session_t (const std::string &host, Poco::UInt16 port) : 
            HTTPClientSession(host, port) {
            };
        virtual ~poco_http_session_t () {};
};

namespace hcm {
    enum IO_STATUS_CODE { OK, FAIL, NOTFOUND };
    class AWSio
    {
        private:
            std::string m_secret_key, m_access_key, m_service, m_host, m_region, m_prefix;
            bool m_secureConnection;

            IO_STATUS_CODE get(const std::string &key, std::string &output_string, int &resp_code);
            IO_STATUS_CODE put(const std::string &key, const std::string &value, int &resp_code);
            IO_STATUS_CODE remove(const std::string &key, int &resp_code);
            IO_STATUS_CODE head(const std::string &key, int &resp_code);
            IO_STATUS_CODE scan(const string &scanstr, string &cont_token, int scan_key_limit, int &resp_code, string &resp_data);
        public:
            AWSio(
                    const std::string &service,
                    const std::string &bucket,
                    const std::string &region,
                    const std::string &secret_key,
                    const std::string &access_key,
                    const std::string &prefix,
                    bool secureConnection
                 );
            ~AWSio();
            std::string post(const std::string &base_uri);
            IO_STATUS_CODE get(const std::string &key, std::string &output_string);
            IO_STATUS_CODE put(const std::string &key, const std::string &value);
            IO_STATUS_CODE remove(const std::string &key);
            IO_STATUS_CODE head(const std::string &key);
            IO_STATUS_CODE scan(const string &scanstr, string &cont_token, string &resp_data, int scan_key_limit = 1000);
            int create_canonical_query_uri(Poco::URI &uri, std::string &canonical_uri, std::string &query_string, const std::string &key, const std::string &prefix);
            bool parseXmlScanResults(string &resp_xml_data, vector<string> &scans, string &nextContinuationToken);
    };
}
#endif
