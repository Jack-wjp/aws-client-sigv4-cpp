#include "awsClient.h"

using std::cout;
using std::cin;
using std::getline;

const std::string RESERVED_PATH        = "?#";
const std::string RESERVED_QUERY       = "?#/:;+@";
const std::string RESERVED_QUERY_PARAM = "?#/:;+@&=";
const std::string RESERVED_FRAGMENT    = "";
const std::string ILLEGAL = "%<>{}|\\\"^`!*'()$,[]";

namespace hcm{
    std::string query_encode_v2(const std::string& str, const std::string& reserved)
    {
        std::string encodedStr;
        for (std::string::const_iterator it = str.begin(); it != str.end(); ++it)
        {
            char c = *it;
            if ((c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '-' || c == '_' ||
                    c == '.' || c == '~')
            {
                encodedStr += c;
            }
            else if (c <= 0x20 || c >= 0x7F || ILLEGAL.find(c) != std::string::npos || reserved.find(c) != std::string::npos)
            {
                encodedStr += '%';
                encodedStr += NumberFormatter::formatHex((unsigned) (unsigned char) c, 2);
            }
            else encodedStr += c;
        }
        //cout << "encodedStr : " << encodedStr << endl;
        return encodedStr;
    }
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
        //cout << "e : " << e.str() << endl;
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

    int AWSS3io::create_canonical_query_uri(Poco::URI &uri, std::string &canonical_uri, std::string &query_string, const std::string &key, const std::string &prefix)
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
            //Poco::URI::encode(p,"", canonical_uri); //Upon POCO update uncomment this statement as this is fixed in latest poco
            canonical_uri = query_encode_v2(p, ""); //Comment this line when above line in being uncommented
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

    IO_STATUS_CODE AWSS3io::send_request(HTTPRequest &request, HTTPResponse &response, Poco::URI &uri, const std::string &authorization, const std::string &date, const std::string &payload_hash, const std::string payload, stringstream &response_body, int &resp_code)
    {
        resp_code = 200;
        try{
            request.setContentType("application/octet-stream");
            request.add("Authorization",authorization);
            request.add("X-Amz-Date", date);
            request.add("X-Amz-Content-Sha256", payload_hash);
            request.add("Accept", "*/*");
            request.add("Accept-Encoding", "gzip, deflate");
            request.setContentLength(0);
            request.setKeepAlive(true);
            if(nullptr == m_network_session)
            {
                m_network_session = new cm_network_session_t(uri.getHost(), uri.getPort(), m_secureConnection);
            }
            // cout << "Request formed" << endl;
            //auto start = chrono::system_clock::now();
            m_network_session->get_network_session()->sendRequest(request);
            // cout << "Request sent" << endl;
            istream & response_body_stream = m_network_session->get_network_session()->receiveResponse(response);
            if(response_body_stream.good()) {
                response_body  <<  response_body_stream.rdbuf();
            }
            //auto now = chrono::system_clock::now();
            //double millisecs = chrono::duration_cast<chrono::milliseconds>(now - start).count();
            //cout << "[send_request::get] : " << uri.getPathAndQuery() << " size : " << response_body.str().size() << " bytes.. time elapsed: " << millisecs << " millisecs. " << endl;
            resp_code = response.getStatus();
        }
        catch ( const Poco::Net::NoMessageException& e )
        {
            std::cerr << "Net::NoMessageException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            delete m_network_session;
            m_network_session = nullptr;
            resp_code = 520;
            return FAIL;
        }
        catch ( const Poco::Net::ConnectionResetException& e )
        {
            std::cerr << "Net::ConnectionResetException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            delete m_network_session;
            m_network_session = nullptr;
            resp_code = 520;
            return FAIL;
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

    IO_STATUS_CODE AWSS3io::scan(const string &scanstr, string &cont_token, int scan_key_limit, int &resp_code, string &resp_data)
    {
        std::string output_string;
        std::vector<string> list_files;
        Poco::URI uri;
        std::string payload_hash = "";
        std::string canonical_uri = "";
        std::string query_prefix = "list-type=2&max-keys=";
        std::string query_prefix_1 = "&prefix=";
        std::string query_prefix_2 = "&continuation-token=";
        std::string query_string = "";
        std::string payload = "";
        stringstream response_body;
        resp_code = 200;
        const time_t sig_time=time(0);
        hcm::Signature signature(m_service, m_host, m_region, m_secret_key, m_access_key, sig_time);

        create_canonical_query_uri(uri, canonical_uri, query_string, "", "");
        //update query for scan
        if(cont_token.length())
        {
            query_string = query_encode(query_prefix + std::to_string(scan_key_limit) + query_prefix_1 + m_prefix.substr(1) + scanstr + query_prefix_2) + query_encode_v2(cont_token, RESERVED_QUERY_PARAM);
        }
        else
        {
            query_string = query_encode(query_prefix + std::to_string(scan_key_limit) + query_prefix_1 + m_prefix.substr(1) + scanstr);
        }
        //cout << "Query String1 : "   << query_string <<  " : " << endl;

        try
        {
            //cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_GET, canonical_uri+"?"+query_string, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(OK != send_request(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body, resp_code)){
                return FAIL;
            }

            if(resp_code / 100 > 2)
            {
                cerr << "server response: " << resp_code << ' ' << response.getReason() << endl;
                cout << "scan response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                //cout << "scan response body  ------  " << response_body.str() << endl;
                resp_data = response_body.str();
                return OK;
            }
        }
        catch(const Poco::Exception& e)
        {
            std::cerr <<  "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " <<  "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
        }
        return FAIL;
    }

    IO_STATUS_CODE AWSS3io::head(const std::string &key, const std::string &type, std::string &output_value_str, int &resp_code)
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
            //cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_HEAD, canonical_uri, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(OK != send_request(request, response, uri, signature.getAuthorization("HEAD", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body, resp_code)){
                return FAIL;
            }
            if(resp_code / 100 > 2)
            {
                cerr << "server response: " << resp_code << ' ' << response.getReason() << endl;
                if(404 == resp_code) 
                {
                    return NOTFOUND;
                }
                cout << "HEAD Response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                cout << "Content Length : " << response.getContentLength() << endl;
                cout << "HEAD Response.. type: " << type << ", value : " << response.get(type) << endl;
                output_value_str = response.get(type);
            }
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

    IO_STATUS_CODE AWSS3io::remove(const std::string &key, int &resp_code)
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
            //cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_DELETE, canonical_uri, HTTPMessage::HTTP_1_1);
            HTTPResponse response;
            if(OK != send_request(request, response, uri, signature.getAuthorization("DELETE", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body, resp_code)){
                return FAIL;
            }
            if(resp_code / 100 > 2)
            {
                cout << "DELETE response body  ------  " << response_body.str() << endl;
                cerr << "server response: " << resp_code << ' ' << response.getReason() << endl;
                return FAIL;
            }
            else
            {
                //cout << "content length : " << response.getcontentlength() << endl;
            }
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

    IO_STATUS_CODE AWSS3io::put(const std::string &key, const std::string &value, int &resp_code)
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
            //cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_PUT, canonical_uri, HTTPMessage::HTTP_1_1);
            request.setContentType("application/octet-stream");
            request.add("Accept", "*/*");
            request.add("Accept-Encoding", "gzip, deflate");
            request.setKeepAlive(true);
            if(nullptr == m_network_session)
            {
                m_network_session = new cm_network_session_t(uri.getHost(), uri.getPort(), m_secureConnection);
            }
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

                //cout << "Request formed" << endl;
                ostream& body_stream = m_network_session->get_network_session()->sendRequest(request);
                //cout << "Request sent" << endl;
                size_t chunk_len;
                //X509Certificate cert = m_network_session->get_network_session()->serverCertificate();
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
                body_stream.flush();
                //cout << "Body sent" << endl;
                //cout << "auth put signature : " << prevSig << " partnum : " << ++partNum << endl << endl;
            }
            else
            {
                request.add("Authorization",signature.getAuthorization("PUT", canonical_uri, query_string, value, payload_hash));
                request.add("X-Amz-Date", signature.getdate());
                request.add("X-Amz-Content-Sha256",payload_hash);
                request.setContentLength(value.size());

                //cout << "Request formed" << endl;
                ostream& body_stream = m_network_session->get_network_session()->sendRequest(request);
                //cout << "Request sent" << endl;
                //X509Certificate cert = m_network_session->get_network_session()->serverCertificate();
                //cout << "Cert common name : " << cert.commonName() << endl;
                body_stream << value;
                body_stream.flush();
                //cout << "Body sent" << endl;
            }
            HTTPResponse response;
            stringstream response_body;
            istream& response_body_stream = m_network_session->get_network_session()->receiveResponse(response);
            resp_code = response.getStatus();
            if(response_body_stream.good()) {
                response_body  <<  response_body_stream.rdbuf();
            }
            if(resp_code / 100 > 2)
            {
                cerr << "server response: " << resp_code << ' ' << response.getReason() << endl;
                cout << "PUT response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                //cout << "content length : " << response.getcontentlength() << endl;
            }
        }
        catch ( const Poco::Net::NoMessageException& e )
        {
            std::cerr << "Net::NoMessageException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            delete m_network_session;
            m_network_session = nullptr;
            resp_code = 520;
            return FAIL;
        }
        catch ( const Poco::Net::ConnectionResetException& e )
        {
            std::cerr << "Net::ConnectionResetException: [" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.message() << std::endl;
            delete m_network_session;
            m_network_session = nullptr;
            resp_code = 520;
            return FAIL;
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

    IO_STATUS_CODE AWSS3io::get(const std::string &key, std::string &output_string, int &resp_code, std::map<string, string> &resp_headers, int offset, int range)
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
            //cout << "host: " << uri.getHost() << " port : " << uri.getPort() << endl;
            HTTPRequest request(HTTPRequest::HTTP_GET, canonical_uri, HTTPMessage::HTTP_1_1); 
            if(range != 0){
                string range_req = "bytes=" + std::to_string(offset) + "-" + std::to_string(offset+range-1);
                request.add("Range",range_req);    
            }                       
            HTTPResponse response;
            if(OK != send_request(request, response, uri, signature.getAuthorization("GET", canonical_uri, query_string, payload, payload_hash), signature.getdate(), payload_hash, payload, response_body, resp_code)){
                return FAIL;
            }
            if(resp_code / 100 > 2)
            {
                cerr << "server response: " << resp_code << ' ' << response.getReason() << endl;
                cout << "GET response body  ------  " << response_body.str() << endl;
                return FAIL;
            }
            else
            {
                //cout << "content length : " << response.getcontentlength() << endl;
                string etag = response.get("etag", "");
                resp_headers["etag"] = etag;
            }
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
        uint retry_count = 0;
        std::cout << "AWSio::put: " << key << std::endl;
        ret = aws_s3_io->put(key, value, resp_code);
        while((500 == resp_code || 520 == resp_code) && retry_count < _MAX_RETRY_COUNT)
        {
            usleep( _RETRY_SLEEP_S * 1000 * 1000);
            retry_count++;
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying ( " << retry_count << " of 5) on response code " << resp_code << "...key : " << key << endl;
            ret = aws_s3_io->put(key, value, resp_code);
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::remove(const std::string &key)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        uint retry_count = 0;
        std::cout << "AWSio::remove: " << key << std::endl;
        ret = aws_s3_io->remove(key, resp_code);
        while((500 == resp_code || 520 == resp_code) && retry_count < _MAX_RETRY_COUNT)
        {
            usleep( _RETRY_SLEEP_S * 1000 * 1000);
            retry_count++;
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying ( " << retry_count << " of 5). on response code " << resp_code << "..key : " << key << endl;
            ret = aws_s3_io->remove(key, resp_code);
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::head(const std::string &key, const std::string &type, std::string &output_value_str)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        uint retry_count = 0;
        std::cout << "AWSio::head: key : " << key << " type : " << type << std::endl;
        ret = aws_s3_io->head(key, type, output_value_str, resp_code);
        while((500 == resp_code || 520 == resp_code) && retry_count < _MAX_RETRY_COUNT)
        {
            usleep( _RETRY_SLEEP_S * 1000 * 1000);
            retry_count++;
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying ( " << retry_count << " of 5) on response code " << resp_code << "...key : " << key << endl;
            ret = aws_s3_io->head(key, type, output_value_str, resp_code);
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::scan(const string &scanstr, string &cont_token, string &resp_data, int scan_key_limit)
    {
        int resp_code = 200;
        IO_STATUS_CODE ret = OK;
        uint retry_count = 0;
        //std::cout << "AWSio::scan: " << scanstr << std::endl;
        ret = aws_s3_io->scan(scanstr, cont_token, scan_key_limit, resp_code, resp_data);
        while((500 == resp_code || 520 == resp_code) && retry_count < _MAX_RETRY_COUNT)
        {
            usleep( _RETRY_SLEEP_S * 1000 * 1000);
            retry_count++;
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying ( " << retry_count << " of 5) on response code " << resp_code << ".....scanstring : " << scanstr << " scan_key_limit : " << scan_key_limit << endl;
            ret = aws_s3_io->scan(scanstr, cont_token, scan_key_limit, resp_code, resp_data);
        }

        if (404 == resp_code)
        {
            return NOTFOUND;
        }
        return ret;
    }

    IO_STATUS_CODE AWSio::get(const std::string &key, std::string &output_string, std::map<string, string> &resp_hdrs, int offset, int range)
    {
        int resp_code = 200;
        std::vector<string> list_files;
        IO_STATUS_CODE ret = OK;
        uint retry_count = 0;
        std::cout << "AWSio::get: " << key << std::endl;
        ret = aws_s3_io->get(key, output_string, resp_code, resp_hdrs, offset, range);
        while((500 == resp_code || 520 == resp_code) && retry_count < _MAX_RETRY_COUNT)
        {
            usleep( _RETRY_SLEEP_S * 1000 * 1000);
            retry_count++;
            cout << "[" << __PRETTY_FUNCTION__ << "]: " << "Retrying ( " << retry_count << " of 5) on response code " << resp_code << "...key : " << key << endl;
            ret = aws_s3_io->get(key, output_string, resp_code, resp_hdrs, offset, range);
        }
        return ret;
    }

#if GTEST
    AWSio::AWSio(MockAWSS3io* paws, bool secureConnection)
#else
    AWSio::AWSio(AWSS3io* paws, bool secureConnection)
#endif
    {
        aws_s3_io = paws;
    }

    AWSio::~AWSio()
    {
        delete aws_s3_io;
    }

    AWSS3io::AWSS3io(const std::string & secret_key, const std::string & access_key, const std::string & service, const std::string & host, const std::string & region, const std::string & prefix, bool secureConnection)
    {
        m_secret_key = secret_key;
        m_access_key = access_key;
        m_service = service;
        m_host = host;
        m_region = region;
        m_prefix = prefix;
        m_secureConnection = secureConnection;
        Poco::URI uri;
        std::string uri_str{(m_secureConnection ? "https://" : "http://") + m_host};
        // cout << "base uri : " << uri_str << endl;
        try
        {
            uri = Poco::URI(uri_str);
        }
        catch (std::exception& e)
        {
            throw std::runtime_error(e.what());
        }
        m_network_session = new cm_network_session_t(uri.getHost(), uri.getPort(), m_secureConnection);
    }

    AWSS3io::~AWSS3io()
    {
        delete m_network_session;
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
        string host = bucket+"."+service+".amazon.aws.com";
#if GTEST
        aws_s3_io = new MockAWSS3io(secret_key, access_key, service, host, region, prefix, secureConnection);
#else
        aws_s3_io = new AWSS3io(secret_key, access_key, service, host, region, prefix, secureConnection);
#endif
    }

}
