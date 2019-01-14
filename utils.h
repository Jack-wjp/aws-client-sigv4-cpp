#ifndef __CM_HTTPS_SESSION_H__
#define __CM_HTTPS_SESSION_H__ 

#include "poco_ssl_initializer.h"
#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/HTTPClientSession.h"
#include <iostream>
#include <sstream> 
#include <cstring>
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/AutoPtr.h"
#include "Poco/DOM/Element.h"
#include "Poco/DOM/Attr.h"
#include "Poco/DOM/Text.h"
#include "Poco/DOM/NamedNodeMap.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/ElementsByTagNameList.h"
#include "Poco/SAX/InputSource.h"
using namespace Poco;
using namespace XML;
using namespace std;
using namespace Net;

#include <unistd.h>
#include <string>
#include <limits.h>
    inline string GetStdoutFromCommand(string cmd) {

        string data;
        FILE * stream;
        const int max_buffer = 256;
        char buffer[max_buffer];
        cmd.append(" 2>&1"); // Do we want STDERR?

        stream = popen(cmd.c_str(), "r");
        if (stream) {
            while (!feof(stream))
                if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
            pclose(stream);
        }
        return data;
    }

    inline bool get_running_binary_path(string &bin_path) {
        char buff[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buff, sizeof(buff)-1);

        if (len != -1) {
            buff[len] = '\0';
            bin_path = std::string(buff);
            return true;
        }
        return false;
    }
    inline bool parse_s3_xml_scan_results(string &resp_xml_data, vector<pair<string, string>> &scans,
            string &nextContinuationToken, string prefix) {
        stringstream response_body;
        DOMParser parser;
        try{
            response_body << resp_xml_data;
            //cout << "  -------------" << resp_xml_data << endl << endl;
            InputSource src { response_body };
            AutoPtr<Document> dom = parser.parse(&src);
            auto pNL1 = dom->getElementsByTagName("IsTruncated");
            auto isTruncated = pNL1->item(0)->innerText();
            pNL1->release();
            if(isTruncated == "true")
            {
                auto pNL2 = dom->getElementsByTagName("NextContinuationToken");
                nextContinuationToken = pNL2->item(0)->innerText();
                pNL2->release();
            }
            else
            {
                nextContinuationToken = "";
            }
            auto node_list = dom->getElementsByTagName("Contents");
            /* Iterate over each content node */
            for (unsigned int idx=0; idx < node_list->length(); idx++) {
                string keyname = "";
                string etag = "";
#ifdef CM_DEBUG
                cout << "node: " << node_list->item(idx)->nodeName() << endl;
                cout << "node hasChildNodes: " << node_list->item(idx)->hasChildNodes() << endl;
                cout << "node len childnodes : " << node_list->item(idx)->childNodes()->length() << endl;
                cout << "node type: " << node_list->item(idx)->nodeType() << endl;
                cout << "node text: " << node_list->item(idx)->innerText() << endl;
#endif
                /* Iterate over each node inside contents node */
                auto content_node_list = node_list->item(idx)->childNodes();
                for (unsigned int kidx=0; kidx < content_node_list->length(); kidx++) {
                    auto node = content_node_list->item(kidx);
                    if (node->nodeName().compare("Key") == 0) {
                        if (node->innerText().back() != '/') {
                            keyname = node->innerText().substr(prefix.length()); //remove the prefix
                        }
                    } else if (node->nodeName().compare("ETag") == 0) {
                        etag = node->innerText();
                    }
                }
                if (keyname.length() > 0 && etag.length() > 0) {
                    scans.push_back(pair<string,string>(keyname, etag));
#ifdef CM_DEBUG
                    cout << "Adding to scan list key:" << keyname << " etag:" << etag << endl;
#endif
                }
                content_node_list->release();
            }
            node_list->release();
        }
        catch(const Poco::Exception& e)
        {
            std::cerr << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << ": " << e.displayText() << std::endl;
            return false;
        }
        catch( const std::exception& e )
        {
            std::cerr << "Caught exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << e.what() << std::endl;;
            return false;
        }
        catch(...)
        {
            std::cerr << "Default exception: " << "[" << __PRETTY_FUNCTION__ << "]: " << std::endl;;
            return false;
        }
        return true;
    }
class cm_https_session_t : public Poco::Net::HTTPSClientSession{
    public:
        cm_https_session_t (const std::string &host, Poco::UInt16 port) : 
            HTTPSClientSession(host, port, poco_ssl_initializar_t::get_client_context()){
            };
        virtual ~cm_https_session_t () {};
};

class cm_http_session_t : public Poco::Net::HTTPClientSession{
    public:
        cm_http_session_t (const std::string &host, Poco::UInt16 port) : 
            HTTPClientSession(host, port){
            };
        virtual ~cm_http_session_t () {};
};

class cm_network_session_t {
    Poco::Net::HTTPClientSession *m_http_c;
    Poco::Net::HTTPSClientSession *m_https_c;
    bool m_secure = true;
    std::string m_host;
    Poco::UInt16 m_port;
    public:
    ~cm_network_session_t()
    {
        if(m_secure)
        {
            delete m_https_c;
        }
        else
        {
            delete m_http_c;
        }
    }
    cm_network_session_t(const std::string &host, Poco::UInt16 port, const bool secure)
    {
        m_host = host;
        m_port = port;
        m_secure = secure;
        if(m_secure)
        {
            m_https_c = new HTTPSClientSession(host, port, poco_ssl_initializar_t::get_client_context());
            m_https_c->setKeepAlive(true);
            m_https_c->setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
        }
        else
        {
            m_http_c = new HTTPClientSession(host, port);
            m_http_c->setKeepAlive(true);
            m_http_c->setTimeout(Poco::Timespan(120, 0)); // setting timeout as 120 seconds
        }
    }

    Poco::Net::HTTPClientSession * get_network_session()
    {
        if(m_secure)
        {
            return m_https_c;
        }
        else
        {
            return m_http_c;
        }
    }
};

#endif //__CM_HTTPS_SESSION_H__
