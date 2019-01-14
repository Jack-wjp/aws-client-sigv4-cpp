#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include "../awssigv4.h"
#include "../awsClient.h"

using namespace std;
using namespace hcm;
using namespace Poco;

int main()
{
    std::string query_args = "";
    std::string output_string = "";
    std::string payload = "";
    std::string path("~/personal/aws-client-sigv4-cpp/tests/");
    cout << " Tests Path : " << path << endl;
    const std::string payload_1{"Action=ListUsers&Version=2017-07-10"};
    std::map<string, string> resp_hdrs;
    bool key_found = false;
    vector <pair<string, string>> scans;

    const std::string service{"s3"};
    const std::string region{"ap-south-1"};  // Region needs to be configured to run the test
    const std::string prefix = "/example_test/";  // key prefix needs to be configured to run the test
    // below keys are taken from 
    //http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html
    const std::string access_key = "AKIAIOSFODNN7EXAMPLE";  // Access key needs to be configured to run the test
    const std::string secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // Secre Key needs to be configured to run the test
    const std::string bucket= "example_bucket";  // bucket (example_bucket) needs to be configured to run the test
    hcm::AWSio awsClient(service, bucket, region, secret_key, access_key, prefix, true);

#if 1
    //Big payload GET and PUT ~ 700 MB
    cout << "0. GET and PUT test big payload: " << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        assert(awsClient.head("test_500_mb_file.bin", etag, output_etag) == OK);
        assert(awsClient.get("test_500_mb_file.bin", output_string, resp_hdrs) == OK);
        ofstream fout("test_500_mb_file.bin", ios::binary | ios::out);
        fout<<output_string;
        fout.close();
        assert(awsClient.remove("test_500_mb_file.bin") == OK);

        stringstream bigbuffer;
        ifstream bigfin("test_500_mb_file.bin", ios::binary | ios::in);
        bigbuffer << bigfin.rdbuf();
        bigfin.close();
        string bigpayload = bigbuffer.str();
        assert(awsClient.put("test_500_mb_file.bin", bigpayload) == OK);
        assert(awsClient.head("test_500_mb_file.bin", etag, output_etag) == OK);
        remove("test_500_mb_file.bin");
    }
#endif

    //Big payload
    cout << "1. GET test big payload: " << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        assert(awsClient.get("test_100_mb_file.bin", output_string, resp_hdrs) == OK);
        ofstream fout("test_100_mb_file.bin", ios::binary | ios::out);
        fout<<output_string;
        fout.close();
        assert(awsClient.remove("test_100_mb_file.bin") == OK);

        stringstream bigbuffer;
        ifstream bigfin("test_100_mb_file.bin", ios::binary | ios::in);
        bigbuffer << bigfin.rdbuf();
        bigfin.close();
        string bigpayload = bigbuffer.str();
        assert(awsClient.put("test_100_mb_file.bin?", bigpayload) == OK);
        assert(awsClient.head("test_100_mb_file.bin", etag, output_etag) == OK);
        //std::string pre_computed_etag("\"8f871a70eea006ed877d7cda25fc763e\"");
        //assert(output_etag == pre_computed_etag);
        //assert(resp_hdrs["etag"] == output_etag);
        remove("test_100_mb_file.bin");
    }
    cout << "2. test big payload: " << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        hcm::AWSio awsClient_2(service, bucket, region, secret_key, access_key, prefix, false);
        stringstream bigbuffer;
        ifstream bigfin(path + "test_pic.png", ios::binary | ios::in);
        bigbuffer << bigfin.rdbuf();
        bigfin.close();
        string bigpayload = bigbuffer.str();
        assert(awsClient_2.put("test_pic.png?" + query_args, bigpayload) == OK);
        assert(awsClient_2.head("test_pic.png", etag, output_etag) == OK);
        //assert(output_etag == "\"e29101383bcb0ec76d93d1536844f319\"");
        assert(awsClient_2.remove("test_pic.png") == OK);
    }

    //Valid payload
    cout << "3. test put payload: " << payload_1 << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        assert(awsClient.put("test_tmpv.json", payload_1) == OK);
        assert(awsClient.head("test_tmpv.json", etag, output_etag) == OK);
        //assert(output_etag == "\"e03d69637ffb4399247a4e84bef9623a\"");
        assert(awsClient.get("test_tmpv.json", output_string, resp_hdrs) == OK);
        cout << "get result: " << output_string << endl;
        assert(get_string_md5(output_string) == get_string_md5(payload_1));
        assert(awsClient.remove("test_tmpv.json") == OK);
    }

    //Empty payload
    cout << "4. test put payload: " << payload << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        assert(awsClient.put("test_tmpe.json", payload) == OK);
        assert(awsClient.head("test_tmpe.json", etag, output_etag) == OK);
        //assert(output_etag1 == "\"d41d8cd98f00b204e9800998ecf8427e\"");
        assert(awsClient.get("test_tmpe.json", output_string, resp_hdrs) == OK);
        //assert(resp_hdrs["etag"] == output_etag1);
        cout << "get result: " << output_string << endl;
        assert(get_string_md5(output_string) == get_string_md5(payload));
        assert(awsClient.remove("test_tmpe.json") == OK);
    }

    //Binary payload
    cout << "5. test get payload: " << "HELLOHELLOHELLOHELLOHELLOHELLO" << endl;
    {
        std::string etag="Etag";
        std::string output_etag;
        assert(awsClient.head("test.pdf?" + query_args, etag, output_etag) == OK);
        //assert(output_etag2 == "\"4ed54b81e051d8f6386d2b19b6e4b576\"");
        assert(awsClient.get("test.pdf?" + query_args, output_string, resp_hdrs) == OK);
        // assert(resp_hdrs["etag"] == output_etag2);
        cout << "get result md5sum: " << get_string_md5(output_string) << endl;
        assert(get_string_md5(output_string) == "HELLOHELLOHELLOHELLOHELLOHELLO");
    }

    {
        std::string etag="Etag";
        std::string output_etag;
        hcm::AWSio awsClient_1(service, bucket, region, secret_key, access_key, prefix, true);
        stringstream buffer;
        ifstream fin(path + "test_pic.png", ios::binary | ios::in);
        buffer << fin.rdbuf();
        fin.close();
        string payload_2 = buffer.str();
        cout << "6. test put payload: " << get_string_md5(payload_2) << endl;
        assert(awsClient_1.put("test_pic.png?" + query_args, payload_2) == OK);
        assert(awsClient_1.head("test_pic.png?" + query_args, etag, output_etag) == OK);
        //assert(output_etag == "\"e29101383bcb0ec76d93d1536844f319\"");
        assert(awsClient_1.get("test_pic.png?" + query_args, output_string, resp_hdrs) == OK);
        //assert(resp_hdrs["etag"] == "\"e29101383bcb0ec76d93d1536844f319\"");
        cout << "get result md5sum: " << get_string_md5(output_string) << endl;
        assert(get_string_md5(output_string) == get_string_md5(payload_2));
        assert(awsClient_1.remove("test_pic.png?" + query_args) == OK);

        //List Files
        key_found = false;
        cout << "7. List Files : " << endl;
        std::string nextContinuationToken="";
        std::string xml_resp_data="";
        awsClient_1.scan("local_job_local", nextContinuationToken, xml_resp_data, 2);
        parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
        cerr << "Scan results:\n";
        for (size_t idx=0; idx < scans.size(); idx++) {
            string result = scans[idx].first;
            cerr << result << endl;
            if ("local_job_local_task_cpp_test" == result) {
                key_found = true;
            }
        }
        assert(key_found);

        {
            std::string etag="Etag";
            std::string output_etag;
            hcm::AWSio awsClient_8(service, bucket, region, secret_key, access_key, prefix, false);
            key_found = false;
            cout << "8. List Files : ref" << endl;
            std::string nextContinuationToken="";
            std::string xml_resp_data="";
            awsClient_8.scan("ref", nextContinuationToken, xml_resp_data, 10);
            parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
            cerr << "Scan results:\n";
            for (pair<string, string> result_pair : scans) {
                cerr << result_pair.first << endl;
                key_found = true;
            }
            assert(key_found);
        }
    }

    {
        std::string etag="Etag";
        std::string output_etag;
        key_found = false;
        cout << "9. List Files : " << endl;
        std::string nextContinuationToken="";
        std::string xml_resp_data="";
        awsClient.scan("test_dir/test_dir", nextContinuationToken, xml_resp_data, 1);
        parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
        cerr << "Scan results:\n";
        for (pair<string, string> result_pair : scans) {
            cerr << result_pair.first << endl;
            key_found = true;
        }
        assert(key_found);
    }

    {
        std::string etag="Etag";
        std::string output_etag;
        hcm::AWSio awsClient_3(service, bucket, region, secret_key, access_key, prefix, true);
        cout << "10. List Files / exclude directories : " << endl;
        std::string nextContinuationToken="";
        std::string xml_resp_data="";
        awsClient_3.scan("test_dir/", nextContinuationToken, xml_resp_data, 5);
        parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
        cerr << "Scan results:\n";
        for (pair<string, string> result_pair : scans) {
            cerr << result_pair.first << endl;
            key_found = true;
        }
        assert(key_found);
    }

    {
        key_found = false;
        cout << "11. List Files : " << endl;
        std::string nextContinuationToken="";
        std::string xml_resp_data="";
        awsClient.scan("test_dir/test_dir/non_existing_test_file", nextContinuationToken, xml_resp_data, 1);
        parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
        assert(scans.size() == 0);
    }
    {
        std::string etag="Etag";
        std::string output_etag;
        cout << "12. HEAD for Key not found  : " << endl;
        assert(awsClient.head("test_dir/test_dir/non_existing_test_file", etag, output_etag) == NOTFOUND);
    }

    {
        std::string etag="Etag";
        std::string output_etag;
        cout << "13. OPTIONS for Key not found  : " << endl;
        assert(awsClient.head("test_dir/test_dir/test.pdf", etag, output_etag) == OK);
    }
    {
        cout << "14. SCAN with continuation Token (secure mode): " << endl;
        hcm::AWSio awsClient_14(service, bucket, region, secret_key, access_key, prefix, true);
        std::string xml_resp_data="";
        string nextContinuationToken = "";
        do{
            awsClient_14.scan("test_", nextContinuationToken, xml_resp_data, 1000);
            parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
            cerr << "Scan results: keycount : " << scans.size() << endl;;
            for (pair<string, string> result_pair : scans) {
                assert(result_pair.first.back() != '/');
                cerr << result_pair.first << endl;
                key_found = true;
            }
            scans.clear();
        }while( nextContinuationToken.length() > 0);
    }
    {
        std::string etag="Etag";
        std::string output_etag;
        cout << "15. SCAN with continuation token (non secure mode): " << endl;
        hcm::AWSio awsClient_15(service, bucket, region, secret_key, access_key, prefix, false);
        std::string xml_resp_data="";
        string nextContinuationToken = "";
        do{
            awsClient_15.scan("test_", nextContinuationToken, xml_resp_data, 1000);
            parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
            cerr << "Scan results: keycount : " << scans.size() << endl;;
            for (pair<string, string> result_pair : scans) {
                assert(result_pair.first.back() != '/');
                cerr << result_pair.first << endl;
                key_found = true;
            }
            scans.clear();
        }while( nextContinuationToken.length() > 0);
    }
    {
        std::string etag="Etag";
        std::string output_etag;
        cout << "16. SCAN with continuation token where only single key is present: " << endl;
        hcm::AWSio awsClient_16(service, bucket, region, secret_key, access_key, prefix, true);
        std::string xml_resp_data="";
        string nextContinuationToken = "";
        do{
            awsClient_16.scan("test_", nextContinuationToken, xml_resp_data, 10);
            parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
            cerr << "Scan results: keycount : " << scans.size() << endl;;
            for (pair<string, string> result_pair : scans) {
                assert(result_pair.first.back() != '/');
                cerr << result_pair.first << endl;
                key_found = true;
            }
            scans.clear();
        }while( nextContinuationToken.length() > 0);
    }

    {
        std::string etag="Etag";
        std::string output_etag;
        cout << "17. SCAN with continuation token with 7 as scan_limit: " << endl;
        hcm::AWSio awsClient_17(service, bucket, region, secret_key, access_key, prefix, true);
        std::string xml_resp_data="";
        string nextContinuationToken = "";
        do{
            awsClient_17.scan("test_di", nextContinuationToken, xml_resp_data, 7);
            parse_s3_xml_scan_results(xml_resp_data, scans, nextContinuationToken, prefix);
            cerr << "Scan results: keycount : " << scans.size() << endl;;
            for (pair<string, string> result_pair : scans) {
                assert(result_pair.first.back() != '/');
                cerr << result_pair.first << endl;
                key_found = true;
            }
            scans.clear();
        }while( nextContinuationToken.length() > 0);
    }

    {
        std::string etag="etag";
        std::string output_etag;
        cout << "17. With special characters in file name .. get head put delete test: " << payload_1 << endl;
        string key_name = "marinv<>{}|\\\"^`!*'()$,[].json"; // % is not allowed getting Poco::URI exception
        assert(awsClient.put(key_name, payload_1) == OK);
        assert(awsClient.head(key_name, etag, output_etag) == OK);
        assert(0 == output_etag.compare("\"e03d69637ffb4399247a4e84bef9623a\""));
        assert(awsClient.get(key_name, output_string, resp_hdrs) == OK);
        assert(resp_hdrs["etag"] == "\"e03d69637ffb4399247a4e84bef9623a\"");
        cout << "get result: " << output_string << endl;
        assert(get_string_md5(output_string) == get_string_md5(payload_1));
        assert(awsClient.remove(key_name) == OK);

    }

    cout << "18. GET only chunk from payload test: " << endl;
    {
        std::string etag="Content-Length";
        std::string output_etag;
        assert(awsClient.head("test_file.txt", etag, output_etag) == OK);
        cout <<"size:" << output_etag << endl;
        assert(awsClient.get("test_file.txt", output_string, resp_hdrs, 0, 8) == OK);
        cout << "get result: " << output_string << endl;
        assert(awsClient.get("test_file.txt", output_string, resp_hdrs, 9, 10) == OK);
        cout << "get result: " << output_string << endl;
        assert(awsClient.get("test_file.txt", output_string, resp_hdrs) == OK);
        cout << "get result: " << output_string << endl;
    }

    return 0;
}
