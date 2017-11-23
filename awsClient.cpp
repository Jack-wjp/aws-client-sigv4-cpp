#include "awsClient.h"

using std::cout;
using std::cin;
using std::getline;

using namespace Poco;
using namespace Net;
using namespace XML;
using namespace std;

namespace hcm{
    std::string query_encode(const std::string &s)
    {
        static const char lookup[]= "0123456789ABCDEF"; //Hex Numbers
        std::stringstream e;
        for(int i=0, ix=s.length(); i<ix; i++)
        {
            const char& c = s[i];
            if ( (48 <= c && c <= 57) ||//0-9
                    (65 <= c && c <= 90) ||//abc...xyz
                    (97 <= c && c <= 122) || //ABC...XYZ
                    (c=='-' || c=='_' || c=='.' || c=='~' || c=='=' || c=='&')  // other than standard  code '=' '&' is also added
               )
            {
                e << c;
            }
            else
            {
                e << '%';
                e << lookup[ (c&0xF0)>>4 ];
                e << lookup[ (c&0x0F) ];
            }
        }
        return e.str();
    }

    std::string urlencode(const std::string &s)
    {
        static const char lookup[]= "0123456789ABCDEF"; //Hex Numbers
        std::stringstream e;
        for(int i=0, ix=s.length(); i<ix; i++)
        {
            const char& c = s[i];
            if ( (48 <= c && c <= 57) ||//0-9
                    (65 <= c && c <= 90) ||//abc...xyz
                    (97 <= c && c <= 122) || //ABC...XYZ
                    (c=='-' || c=='_' || c=='.' || c=='~')
               )
            {
                e << c;
            }
            else
            {
                e << '%';
                e << lookup[ (c&0xF0)>>4 ];
                e << lookup[ (c&0x0F) ];
            }
        }
        return e.str();
    }

    int AWSio::create_canonical_query_uri(Poco::URI &uri, std::string &canonical_uri, std::string &query_string, const std::string &key, const std::string &prefix)
    {
        std::string uri_str{(m_secureConnection ? "https://" : "http://") + m_host + prefix + key};
        // cout << "base uri : " << uri_str << endl;
        try
        {
            uri = Poco::URI(uri_str);
        }
        catch (std::exception& e)
        {
            throw std::runtime_error(e.what());
        }
        const auto p = uri.getPath();
        if (!p.empty())
        {
            Poco::URI::encode(p,"", canonical_uri);
        }
        else
        {
            canonical_uri = "/";
        }

        //query
        const auto query = uri.getQuery();
        if (!query.empty())
        {
            Poco::URI::encode(query,"", query_string);
        }
        else
        {
            query_string = "";
        }

        uri.normalize();
        return 0;
    }

    IO_STATUS_CODE send_request_secure_connection(HTTPRequest &request, HTTPResponse &response, Poco::URI &uri, const std::string &authorization, const std::string &date, const std::string &payload_hash, const std::string payload, stringstream &response_body)
    {
        try{
            request.setContentType("application/octet-stream");
            request.add("Authorization",authorization);
            request.add("X-Amz-Date", date);
            request.add("X-Amz-Content-Sha256", payload_hash);
            request.add("Accept", "*/*");
            request.add("Accept-Encoding", "gzip, deflate");
            poco_https_session_t http_session(uri.getHost(), uri.getPort());
            http_session.setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
            // cout << "Request formed" << endl;
            http_session.sendRequest(request);
            // cout << "Request sent" << endl;
            //X509Certificate cert = http_session.serverCertificate();
            //cout << "Cert common name : " << cert.commonName() << endl;
            istream & response_body_stream = http_session.receiveResponse(response);
            if(response_body_stream.good()) {
                response_body  <<  response_body_stream.rdbuf();
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        return OK;
    }

    IO_STATUS_CODE send_request_nonsecure_connection(HTTPRequest &request, HTTPResponse &response, Poco::URI &uri, const std::string &authorization, const std::string &date, const std::string &payload_hash, const std::string payload, stringstream &response_body)
    {
        try{
            request.setContentType("application/octet-stream");
            request.add("Authorization",authorization);
            request.add("X-Amz-Date", date);
            request.add("X-Amz-Content-Sha256", payload_hash);
            request.add("Accept", "*/*");
            request.add("Accept-Encoding", "gzip, deflate");
            poco_http_session_t http_session(uri.getHost(), uri.getPort());
            http_session.setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
            // cout << "Request formed" << endl;
            http_session.sendRequest(request);
            // cout << "Request sent" << endl;
            istream & response_body_stream = http_session.receiveResponse(response);
            if(response_body_stream.good()) {
                response_body  <<  response_body_stream.rdbuf();
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        return OK;
    }

    vector<string> AWSio::scan(const string &scanstr, int scan_key_limit, int &resp_code)
    {
        std::string output_string;
        std::vector<string> list_files;
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_prefix = "list-type=2&max-keys=";
        std::string query_prefix_1 = "&prefix=";
        std::string query_string = "";
        std::string payload = "";
        stringstream response_body;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host, m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, "", "");
        //update query for scan
        query_string = query_prefix + std::to_string(scan_key_limit) + query_prefix_1 + m_prefix.substr(1) + scanstr;
        // cout << "Query String1 : "   << query_encode(query_string) << endl;

        try
        {
            // cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_GET, canonical_uri+"?"+query_string, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(m_secureConnection)
            {
                if(OK != send_request_secure_connection(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_encode(query_string), payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return list_files;
                }
            }
            else
            {
                if(OK != send_request_nonsecure_connection(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_encode(query_string), payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return list_files;
                }
            }
            cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
            resp_code = response.getStatus();
            if(response.getStatus() / 100 > 2)
            {
                cout << "scan response body  ------  " << response_body.str() << endl;
                return list_files;
            }
            else
            {
                InputSource src { response_body };
                DOMParser parser;
                AutoPtr<Document> dom = parser.parse(&src);
                auto list = dom->getElementsByTagName("Key");

                for (unsigned long index = 0; index < list->length(); ++index)
                {
                    auto keyname = list->item(index)->innerText();
                    if (keyname.back()!='/') {
                        list_files.push_back(keyname.substr(m_prefix.length()-1)); //remove the prefix
                    }
                }
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr <<  "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " <<  "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
        }
        return list_files;
    }

    IO_STATUS_CODE AWSio::head(const std::string &key, int &resp_code)
    {
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_string = "";
        std::string payload = "";
        stringstream response_body;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host,m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, key, m_prefix);
        try
        {
            cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_HEAD, canonical_uri, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(m_secureConnection)
            {
                if(OK != send_request_secure_connection(request, response, uri, signature.getAuthorization("HEAD", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            else
            {
                if(OK != send_request_nonsecure_connection(request, response, uri, signature.getAuthorization("HEAD", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
            resp_code = response.getStatus();
            if(response.getStatus() / 100 > 2)
            {
                if(404 == response.getStatus())
                {
                    return NOTFOUND;
                }
                cout << "HEAD Response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                cout << "Content Length : " << response.getContentLength() << endl;
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        return OK;
    }

    IO_STATUS_CODE AWSio::remove(const std::string &key, int &resp_code)
    {
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_string = "";
        std::string payload = "";
        stringstream response_body;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host,m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, key, m_prefix);
        try
        {
            cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_DELETE, canonical_uri, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(m_secureConnection)
            {
                if(OK != send_request_secure_connection(request, response, uri, signature.getAuthorization("DELETE", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            else
            {
                if(OK != send_request_nonsecure_connection(request, response, uri, signature.getAuthorization("DELETE", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
            resp_code = response.getStatus();
            if(response.getStatus() / 100 > 2)
            {
                cout << "DELETE response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                //cout << "content length : " << response.getcontentlength() << endl;
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        return OK;
    }

    IO_STATUS_CODE AWSio::put(const std::string &key, const std::string &value, int &resp_code)
    {
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_string = "";
        size_t chunk_size = 1024 * 1024 * 5 ;
        size_t total_size = value.length();
        int partNum = 0;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host,m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, key, m_prefix);
        try
        {
            if(m_secureConnection)
            {
                poco_https_session_t http_session(uri.getHost(), uri.getPort());
                http_session.setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
                cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
                HTTPRequest request(HTTPRequest::HTTP_PUT, canonical_uri, HTTPMessage::HTTP_1_1);
                request.setContentType("application/octet-stream");
                request.add("Accept", "*/*");
                request.add("Accept-Encoding", "gzip, deflate");
                if(total_size > chunk_size)
                {
                    std::string authorization = signature.getAuthorization("PUT", canonical_uri, query_string, value, payload_hash, SEED_CHUNK);
                    request.add("Authorization",authorization);
                    request.add("content-encoding", "aws-chunked");
                    request.add("x-amz-decoded-content-length", std::to_string(total_size));
                    request.add("X-Amz-Date", signature.getdate());
                    request.add("X-Amz-Content-Sha256",payload_hash);
                    //request.add("x-amz-storage-class","REDUCED_REDUNDANCY");
                    request.setContentLength(signature.calculateContentLength(total_size, chunk_size));
                    //int s = signature.calculateContentLength(66560, 65536); // output : 66824
                    auto prevSig = authorization.substr(authorization.find("Signature=") + 10 );
                    //cout << "auth put signature : " << prevSig << endl;

                    cout << "Request formed" << endl;
                    ostream& body_stream = http_session.sendRequest(request);
                    cout << "Request sent" << endl;
                    size_t chunk_len;
                    //X509Certificate cert = http_session.serverCertificate();
                    //cout << "Cert common name : " << cert.commonName() << endl;
                    for (size_t rangeStart = 0; rangeStart < total_size; rangeStart += chunk_size)
                    {
                        int end = min(static_cast<int>(rangeStart + chunk_size), static_cast<int>(value.length()));
                        partNum++;
                        chunk_len = end-rangeStart;
                        //cout << "================= : " << value.substr(rangeStart, chunk_len) << endl ;

                        std::string chunkStringtoSign = signature.createChunkStringtoSign(prevSig, chunk_len, value.substr(rangeStart, chunk_len));
                        //cout << "chunk srting to sign: " << chunkStringtoSign << " chunk size : " << chunk_len << endl;
                        prevSig = signature.createSignature(chunkStringtoSign);
                        body_stream << signature.createChunkData(prevSig, chunk_len, value.substr(rangeStart, chunk_len));
                        //cout << "auth put signature : " << prevSig << " partnum : " << partNum << endl;
                    }

                    std::string chunkStringtoSign = signature.createChunkStringtoSign(prevSig, 0, "");
                    //cout << "chunk srting to sign: " << chunkStringtoSign << " chunk size : 0" << endl;
                    prevSig = signature.createSignature(chunkStringtoSign);
                    body_stream << signature.createChunkData(prevSig, 0, "");
                    //cout << "auth put signature : " << prevSig << " partnum : " << ++partNum << endl << endl;
                }
                else
                {
                    request.add("Authorization",signature.getAuthorization("PUT", canonical_uri, query_string, value, payload_hash));
                    request.add("X-Amz-Date", signature.getdate());
                    request.add("X-Amz-Content-Sha256",payload_hash);
                    request.setContentLength(value.size());

                    cout << "Request formed" << endl;
                    ostream& body_stream = http_session.sendRequest(request);
                    cout << "Request sent" << endl;
                    //X509Certificate cert = http_session.serverCertificate();
                    //cout << "Cert common name : " << cert.commonName() << endl;
                    body_stream << value;
                }
                HTTPResponse response;
                stringstream response_body;
                istream& response_body_stream = http_session.receiveResponse(response);
                cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                resp_code = response.getStatus();
                if(response_body_stream.good()) {
                    response_body  <<  response_body_stream.rdbuf();
                }
                if(response.getStatus() / 100 > 2)
                {
                    cout << "PUT response body  ------  " << response_body.str() << endl;
                    return FAIL;
                }
                else
                {
                    //cout << "content length : " << response.getcontentlength() << endl;
                }
            }
            else
            {
                poco_http_session_t http_session(uri.getHost(), uri.getPort());
                http_session.setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
                cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
                HTTPRequest request(HTTPRequest::HTTP_PUT, canonical_uri, HTTPMessage::HTTP_1_1);
                request.setContentType("application/octet-stream");
                request.add("Accept", "*/*");
                request.add("Accept-Encoding", "gzip, deflate");
                if(total_size > chunk_size)
                {
                    std::string authorization = signature.getAuthorization("PUT", canonical_uri, query_string, value, payload_hash, SEED_CHUNK);
                    request.add("Authorization",authorization);
                    request.add("content-encoding", "aws-chunked");
                    request.add("x-amz-decoded-content-length", std::to_string(total_size));
                    request.add("X-Amz-Date", signature.getdate());
                    request.add("X-Amz-Content-Sha256",payload_hash);
                    //request.add("x-amz-storage-class","REDUCED_REDUNDANCY");
                    request.setContentLength(signature.calculateContentLength(total_size, chunk_size));
                    //int s = signature.calculateContentLength(66560, 65536); // output : 66824
                    auto prevSig = authorization.substr(authorization.find("Signature=") + 10 );
                    //cout << "auth put signature : " << prevSig << endl;

                    cout << "Request formed" << endl;
                    ostream& body_stream = http_session.sendRequest(request);
                    cout << "Request sent" << endl;
                    size_t chunk_len;
                    for (size_t rangeStart = 0; rangeStart < total_size; rangeStart += chunk_size)
                    {
                        int end = min(static_cast<int>(rangeStart + chunk_size), static_cast<int>(value.length()));
                        partNum++;
                        chunk_len = end-rangeStart;
                        //cout << "================= : " << value.substr(rangeStart, chunk_len) << endl ;

                        std::string chunkStringtoSign = signature.createChunkStringtoSign(prevSig, chunk_len, value.substr(rangeStart, chunk_len));
                        //cout << "chunk srting to sign: " << chunkStringtoSign << " chunk size : " << chunk_len << endl;
                        prevSig = signature.createSignature(chunkStringtoSign);
                        body_stream << signature.createChunkData(prevSig, chunk_len, value.substr(rangeStart, chunk_len));
                        //cout << "auth put signature : " << prevSig << " partnum : " << partNum << endl;
                    }

                    std::string chunkStringtoSign = signature.createChunkStringtoSign(prevSig, 0, "");
                    //cout << "chunk srting to sign: " << chunkStringtoSign << " chunk size : 0" << endl;
                    prevSig = signature.createSignature(chunkStringtoSign);
                    body_stream << signature.createChunkData(prevSig, 0, "");
                    //cout << "auth put signature : " << prevSig << " partnum : " << ++partNum << endl << endl;
                }
                else
                {
                    request.add("Authorization",signature.getAuthorization("PUT", canonical_uri, query_string, value, payload_hash));
                    request.add("X-Amz-Date", signature.getdate());
                    request.add("X-Amz-Content-Sha256",payload_hash);
                    request.setContentLength(value.size());

                    cout << "Request formed" << endl;
                    ostream& body_stream = http_session.sendRequest(request);
                    cout << "Request sent" << endl;
                    body_stream << value;
                }
                HTTPResponse response;
                stringstream response_body;
                istream& response_body_stream = http_session.receiveResponse(response);
                cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                resp_code = response.getStatus();
                if(response_body_stream.good()) {
                    response_body  <<  response_body_stream.rdbuf();
                }
                if(response.getStatus() / 100 > 2)
                {
                    cout << "PUT response body  ------  " << response_body.str() << endl;
                    return FAIL;
                }
                else
                {
                    //cout << "content length : " << response.getcontentlength() << endl;
                }
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        return OK;
    }

    IO_STATUS_CODE AWSio::get(const std::string &key, std::string &output_string, int &resp_code)
    {
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_string = "";
        std::string payload = "";
        stringstream response_body;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host,m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, key, m_prefix);
        try
        {
            cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_GET, canonical_uri, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(m_secureConnection)
            {
                if(OK != send_request_secure_connection(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            else
            {
                if(OK != send_request_nonsecure_connection(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body)){
                    cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
                    resp_code = response.getStatus();
                    return FAIL;
                }
            }
            cerr << "server response: " << response.getStatus() << ' ' << response.getReason() << endl;
            resp_code = response.getStatus();
            if(response.getStatus() / 100 > 2)
            {
                cout << "GET response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                //cout << "content length : " << response.getcontentlength() << endl;
            }
        }
        catch ( const Poco::Net::SSLException& e )
        {
            std::cerr << "Net::SSLException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            return FAIL;
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return FAIL;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return FAIL;
        }
        output_string = response_body.str();
        return OK;
    }

    IO_STATUS_CODE AWSio::put(const std::string &key, const std::string &value)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        ret = put(key, value, resp_code);
        if(500 == resp_code)
        {
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying..." << endl;
            return put(key, value, resp_code);
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::remove(const std::string &key)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        ret = remove(key, resp_code);
        if(500 == resp_code)
        {
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying..." << endl;
            return remove(key, resp_code);
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::head(const std::string &key)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        ret = head(key, resp_code);
        if(500 == resp_code)
        {
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying..." << endl;
            return head(key, resp_code);
        }
        return ret;
    }

    vector<string> AWSio::scan(const string &scanstr, int scan_key_limit)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        list_files = scan(scanstr, scan_key_limit, resp_code);
        if(500 == resp_code)
        {
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying..." << endl;
            list_files = scan(scanstr, scan_key_limit, resp_code);
        }
        return list_files;
    }

    IO_STATUS_CODE AWSio::get(const std::string &key, std::string &output_string)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        ret = get(key, output_string, resp_code);
        if(500 == resp_code)
        {
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying..." << endl;
            return get(key, output_string, resp_code);
        }
        return ret;
    }

    AWSio::AWSio(
            const std::string &service,
            const std::string &bucket,
            const std::string &region,
            const std::string &secret_key,
            const std::string &access_key,
            const std::string &prefix,
            bool secureConnection
            )
    {
        m_service = service;
        m_host = bucket+"."+service+".amazon.aws.com";
        m_region = region;
        m_secret_key = secret_key;
        m_access_key = access_key;
        m_prefix =  prefix;
        m_secureConnection = secureConnection;
    }

    AWSio::~AWSio()
    {
    }
}
