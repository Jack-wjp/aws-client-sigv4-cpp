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
    bool key_found = false;
    vector <string> scans;
    Object::Ptr pObj;

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
        assert(awsClient.head("test_500_mb_file.bin") == OK);
        assert(awsClient.get("test_500_mb_file.bin", output_string) == OK);
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
        assert(awsClient.head("test_500_mb_file.bin") == OK);
        remove("test_500_mb_file.bin");
    }
#endif

    //Big payload
    cout << "1. GET test big payload: " << endl;
    {
        assert(awsClient.get("test_100_mb_file.bin", output_string) == OK);
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
        assert(awsClient.head("test_100_mb_file.bin") == OK);
        remove("test_100_mb_file.bin");
    }
    cout << "2. test big payload: " << endl;
    {
        hcm::AWSio awsClient_2(service, bucket, region, secret_key, access_key, prefix, false);
        stringstream bigbuffer;
        ifstream bigfin(path + "test_pic.png", ios::binary | ios::in);
        bigbuffer << bigfin.rdbuf();
        bigfin.close();
        string bigpayload = bigbuffer.str();
        assert(awsClient_2.put("test_pic.png?" + query_args, bigpayload) == OK);
        assert(awsClient_2.head("test_pic.png") == OK);
        assert(awsClient_2.remove("test_pic.png") == OK);
    }

    //Valid payload
    cout << "3. test put payload: " << payload_1 << endl;
    assert(awsClient.put("test_tmpv.json", payload_1) == OK);
    assert(awsClient.head("test_tmpv.json") == OK);
    assert(awsClient.get("test_tmpv.json", output_string) == OK);
    cout << "get result: " << output_string << endl;
    assert(get_string_md5(output_string) == get_string_md5(payload_1));
    assert(awsClient.remove("test_tmpv.json") == OK);

    //Empty payload
    cout << "4. test put payload: " << payload << endl;
    assert(awsClient.put("test_tmpe.json", payload) == OK);
    assert(awsClient.head("test_tmpe.json") == OK);
    assert(awsClient.get("test_tmpe.json", output_string) == OK);
    cout << "get result: " << output_string << endl;
    assert(get_string_md5(output_string) == get_string_md5(payload));
    assert(awsClient.remove("test_tmpe.json") == OK);

    //Binary payload
    cout << "5. test get payload: " << "HELLOHELLOHELLOHELLOHELLOHELLO" << endl;
    assert(awsClient.head("test.pdf?" + query_args) == OK);
    assert(awsClient.get("test.pdf?" + query_args, output_string) == OK);
    cout << "get result md5sum: " << get_string_md5(output_string) << endl;
    assert(get_string_md5(output_string) == "HELLOHELLOHELLOHELLOHELLOHELLO");
   
    {
        hcm::AWSio awsClient_1(service, bucket, region, secret_key, access_key, prefix, true);
        stringstream buffer;
        ifstream fin(path + "test_pic.png", ios::binary | ios::in);
        buffer << fin.rdbuf();
        fin.close();
        string payload_2 = buffer.str();
        cout << "6. test put payload: " << get_string_md5(payload_2) << endl;
        assert(awsClient_1.put("test_pic.png?" + query_args, payload_2) == OK);
        assert(awsClient_1.head("test_pic.png?" + query_args) == OK);
        assert(awsClient_1.get("test_pic.png?" + query_args, output_string) == OK);
        cout << "get result md5sum: " << get_string_md5(output_string) << endl;
        assert(get_string_md5(output_string) == get_string_md5(payload_2));
        assert(awsClient_1.remove("test_pic.png?" + query_args) == OK);

        //List Files
        key_found = false;
        cout << "7. List Files : " << endl;
        scans = awsClient_1.scan("local_job_local", 2);
        cerr << "Scan results:\n";
        for (string result : scans) {
            cerr << result << endl;
            if ("cpp_test" == result) {
                key_found = true;
            }
        }
        assert(key_found);

        {
            hcm::AWSio awsClient_8(service, bucket, region, secret_key, access_key, prefix, false);
            key_found = false;
            cout << "8. List Files : ref" << endl;
            scans = awsClient_8.scan("ref", 10);
            cerr << "Scan results:\n";
            for (string result : scans) {
                cerr << result << endl;
                key_found = true;
            }
            assert(key_found);
        }
    }

    key_found = false;
    cout << "9. List Files : " << endl;
    scans = awsClient.scan("test_dir/test_dir", 1);
    cerr << "Scan results:\n";
    for (string result : scans) {
        cerr << result << endl;
        key_found = true;
    }
    assert(key_found);

    {
        hcm::AWSio awsClient_3(service, bucket, region, secret_key, access_key, prefix, true);
        cout << "10. List Files / exclude directories : " << endl;
        scans = awsClient_3.scan("test_dir/", 5);
        cerr << "Scan results:\n";
        for (string result : scans) {
            assert(result.back() != '/');
            cerr << result << endl;
        }
    }

    key_found = false;
    cout << "11. List Files : " << endl;
    scans = awsClient.scan("test_dir/test_dir/non_existing_test_file", 1);
    assert(scans.size() == 0);

    cout << "12. HEAD for Key not found  : " << endl;
    assert(awsClient.head("test_dir/test_dir/non_existing_test_file") == NOTFOUND);

    cout << "13. OPTIONS for Key not found  : " << endl;
    assert(awsClient.head("test_dir/test_dir/test.pdf") == OK);

    return 0;
}
