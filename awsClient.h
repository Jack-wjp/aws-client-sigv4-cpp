#ifndef AWS_CLIENT_H
#define AWS_CLIENT_H

#if GTEST
#include "gmock/gmock.h"
#endif
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
#include "utils.h"

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

namespace hcm {

    enum IO_STATUS_CODE { OK, FAIL, NOTFOUND };
    class AWSS3io
    {
        private:
            std::string m_secret_key, m_access_key, m_service, m_host, m_region, m_prefix;
            bool m_secureConnection;

        public:
            IO_STATUS_CODE get(const std::string &key, std::string &output_string, int &resp_code, std::map<string, string> &response_headers, int offset=0, int range=0);
            IO_STATUS_CODE put(const std::string &key, const std::string &value, int &resp_code);
            IO_STATUS_CODE remove(const std::string &key, int &resp_code);
            IO_STATUS_CODE head(const std::string &key, const std::string &type, std::string &output_value_str, int &resp_code);
            IO_STATUS_CODE scan(const string &scanstr, string &cont_token, int scan_key_limit, int &resp_code, string &resp_data);
            AWSS3io(const std::string & secret_key, const std::string & access_key, const std::string & service, const std::string & host, const std::string & region, const std::string & prefix, bool secureConnection = true);
            ~AWSS3io();
            int create_canonical_query_uri(Poco::URI &uri, std::string &canonical_uri, std::string &query_string, const std::string &key, const std::string &prefix);
            IO_STATUS_CODE send_request(HTTPRequest &request, HTTPResponse &response, Poco::URI &uri, const std::string &authorization, const std::string &date, const std::string &payload_hash, const std::string payload, stringstream &response_body, int &resp_code);

            cm_network_session_t *m_network_session = nullptr;
    };
#if GTEST
    class MockAWSS3io
    {
        private:
            std::string m_secret_key, m_access_key, m_service, m_host, m_region, m_prefix;
            bool m_secureConnection;

        public:
            MockAWSS3io(Json::Value device_io_config, bool secureConnection = true);
            MockAWSS3io(const std::string & secret_key, const std::string & access_key, const std::string & service, const std::string & host, const std::string & region, const std::string & prefix, bool secureConnection = true)
            {
                m_secret_key = secret_key;
                m_access_key = access_key;
                m_service = service;
                m_host = host;
                m_region = region;
                m_prefix = prefix;
                m_secureConnection = secureConnection;
            }
            ~MockAWSS3io() {}
            MOCK_METHOD6(get, IO_STATUS_CODE(const std::string &key, std::string &output_string, int &resp_code, std::map<string, string>&response_headers, int offset, int range));
            MOCK_METHOD3(put, IO_STATUS_CODE(const std::string &key, const std::string &value, int &resp_code));
            MOCK_METHOD2(remove, IO_STATUS_CODE(const std::string &key, int &resp_code));
            MOCK_METHOD4(head, IO_STATUS_CODE(const std::string &key, const std::string &etag, std::string &output_value_str, int &resp_code));
            MOCK_METHOD5(scan, IO_STATUS_CODE(const string &scanstr, string &cont_token, int scan_key_limit, int &resp_code, string &resp_data));
            MOCK_METHOD5(create_canonical_query_uri, int(Poco::URI &uri, std::string &canonical_uri, std::string &query_string, const std::string &key, const std::string &prefix));
            cm_network_session_t *m_network_session = nullptr;
    };
#endif

    class AWSio
    {
        public:
            AWSio(Json::Value device_io_config, bool secureConnection = true);
#if GTEST
            AWSio(MockAWSS3io* paws, bool secureConnection);
#else
            AWSio(AWSS3io* paws, bool secureConnection);
#endif
            ~AWSio();
            IO_STATUS_CODE get(const std::string &key, std::string &output_string, std::map<string, string> &response_headers, int offset=0, int range=0);
            IO_STATUS_CODE put(const std::string &key, const std::string &value);
            IO_STATUS_CODE remove(const std::string &key);
            IO_STATUS_CODE head(const std::string &key, const std::string &type, std::string &output_value_str);
            IO_STATUS_CODE scan(const string &scanstr, string &cont_token, string &resp_data, int scan_key_limit = 1000);

            uint _MAX_RETRY_COUNT = 5;
            double _RETRY_SLEEP_S = 5;
            AWSio(
                    const std::string &service,
                    const std::string &bucket,
                    const std::string &region,
                    const std::string &secret_key,
                    const std::string &access_key,
                    const std::string &prefix,
                    bool secureConnection
                 );

#if GTEST
            MockAWSS3io* aws_s3_io = nullptr;
#else
            AWSS3io* aws_s3_io = nullptr;
#endif
    };
}
#endif
