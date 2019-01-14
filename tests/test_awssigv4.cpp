#include "gtest/gtest.h"
#include <iostream>
#include "fstream"
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <cassert>

#include "../awssigv4.h"
#include "../utils.h"
#include "Poco/Path.h"
using namespace hcm;
using namespace std;
std::string test_path;

std::string GetWholeFile(std::string file_name_str)
{
    std::string file_name = test_path + file_name_str;
    std::ifstream whole_file(file_name.c_str(), std::ios::in|std::ios::binary);
    std::stringstream whole_file_stream;
    whole_file_stream << whole_file.rdbuf();
    std::string whole_file_str = whole_file_stream.str();

    std::string::size_type rpos = 0;
    while ( ( rpos = whole_file_str.find ("\r", rpos) ) != std::string::npos )
    {
        whole_file_str.erase ( rpos, 1);
    }

    return whole_file_str;
}


std::string GetCreateCanonicalRequest(std::string req_file_str)
{
    std::string req_file = test_path + req_file_str;
    std::ifstream reqfile(req_file.c_str(), std::ios::in|std::ios::binary);

    std::string line;
    std::string method, canonical_uri, protocal, payload;
    std::map<std::string, std::vector<std::string> > header_map;
    if (reqfile.is_open())
    {
        int line_count=0;
        while (getline(reqfile, line))
        {
            std::string::size_type rpos = 0;
            while ( ( rpos = line.find ("\r", rpos) ) != std::string::npos )
            {
                line.erase ( rpos, 1);
            }

            if (line_count == 0)
            {
                std::stringstream linestream(line);
                linestream >> method >> canonical_uri >> protocal;
            }
            else
            {
                 std::size_t pos = line.find(":");
                 if (pos != std::string::npos)
                {
                    std::string header, value;
                    header = line.substr(0, pos);
                    value = line.substr(pos+1);

                    if (header_map.find(header) == header_map.end())
                    {
                        header_map[header];
                    }

                    header_map[header].push_back(value);
                }
                else
                {
                 std::size_t epos = line.find("=");
                 if (epos != std::string::npos)
                     payload += line;
                }
            }

            line_count++;
        }
    }

    hcm::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE"
    );

    std::size_t qpos = canonical_uri.find("?");
    std::string canonical_base_uri = canonical_uri;
    std::string query_string = "";

    if (qpos != std::string::npos)
    {
        canonical_base_uri = canonical_uri.substr(0,qpos);
        query_string = canonical_uri.substr(qpos+1);
    }
    return signature.createCanonicalRequest(method, canonical_base_uri, query_string, header_map, payload, SINGLE_CHUNK);
}


std::string GetCreateStringToSign(std::string creq_file)
{
    std::string canonical_request = GetWholeFile(creq_file);

    time_t rawtime;
    time ( &rawtime );
    struct tm * timeinfo = gmtime ( &rawtime );
    timeinfo->tm_year = 2011 - 1900;
    timeinfo->tm_mon = 9 - 1;
    timeinfo->tm_mday = 9;
    timeinfo->tm_hour = 23;
    timeinfo->tm_min = 36;
    timeinfo->tm_sec = 0;

    time_t sig_time = mktime( timeinfo ) - timezone;

    hcm::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE",
        sig_time
    );

    return signature.createStringToSign(canonical_request);
}


std::string GetAuthorizationHeader(std::string req_file_str, std::string sts_file)
{
    std::string req_file = test_path + req_file_str;
    std::ifstream reqfile(req_file.c_str(), std::ios::in|std::ios::binary);

    std::string line;
    std::string method, canonical_uri, protocal, payload;
    std::map<std::string, std::vector<std::string> > header_map;
    if (reqfile.is_open())
    {
        int line_count=0;
        while (getline(reqfile, line))
        {
            std::string::size_type rpos = 0;
            while ( ( rpos = line.find ("\r", rpos) ) != std::string::npos )
            {
                line.erase ( rpos, 1);
            }

            if (line_count == 0)
            {
                std::stringstream linestream(line);
                linestream >> method >> canonical_uri >> protocal;
            }
            else
            {
                 std::size_t pos = line.find(":");
                 if (pos != std::string::npos)
                {
                    std::string header, value;
                    header = line.substr(0, pos);
                    value = line.substr(pos+1);

                    if (header_map.find(header) == header_map.end())
                    {
                        header_map[header];
                    }

                    header_map[header].push_back(value);
                }
                else
                {
                 std::size_t epos = line.find("=");
                 if (epos != std::string::npos)
                     payload += line;
                }
            }

            line_count++;
        }
    }

    time_t rawtime;
    time ( &rawtime );
    struct tm * timeinfo = gmtime ( &rawtime );
    timeinfo->tm_year = 2011 - 1900;
    timeinfo->tm_mon = 9 - 1;
    timeinfo->tm_mday = 9;
    timeinfo->tm_hour = 23;
    timeinfo->tm_min = 36;
    timeinfo->tm_sec = 0;

    time_t sig_time = mktime( timeinfo ) - timezone;

    hcm::Signature signature(
        "host",
        "host.foo.com",
        "us-east-1",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "AKIDEXAMPLE",
        sig_time
    );

    std::size_t qpos = canonical_uri.find("?");
    std::string canonical_base_uri = canonical_uri;
    std::string query_string = "";

    if (qpos != std::string::npos)
    {
        canonical_base_uri = canonical_uri.substr(0,qpos);
        query_string = canonical_uri.substr(qpos+1);
    }

    signature.createCanonicalRequest(method, canonical_base_uri, query_string, header_map, payload, SINGLE_CHUNK);

    std::string string_to_sign = GetWholeFile(sts_file.c_str());

    std::string signature_str = signature.createSignature(string_to_sign);

    return signature.createAuthorizationHeader(signature_str);
}

// Task 1: Create a Canonical Request for Signature Version 4

TEST(createCanonicalRequest, get_header_key_duplicate)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-header-key-duplicate.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-header-key-duplicate.creq"));
}

TEST(createCanonicalRequest, get_header_value_order)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-header-value-order.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-header-value-order.creq"));
}


TEST(createCanonicalRequest, get_header_value_trim)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-header-value-trim.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-header-value-trim.creq"));
}


TEST(createCanonicalRequest, get_vanilla)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla.creq"));
}


TEST(createCanonicalRequest, get_vanilla_empty_query_key)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-empty-query-key.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-empty-query-key.creq"));
}

TEST(createCanonicalRequest, get_vanilla_query)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-query.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-query.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_key)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-query-order-key.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-query-order-key.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_key_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-query-order-key-case.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-query-order-key-case.creq"));
}


TEST(createCanonicalRequest, get_vanilla_query_order_value)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-query-order-value.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-query-order-value.creq"));
}


TEST(createCanonicalRequest,get_vanilla_query_unreserved)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/get-vanilla-query-unreserved.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/get-vanilla-query-unreserved.creq"));
}


TEST(createCanonicalRequest,post_header_key_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-header-key-case.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-header-key-case.creq"));
}


TEST(createCanonicalRequest,post_header_key_sort)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-header-key-sort.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-header-key-sort.creq"));
}


TEST(createCanonicalRequest,post_header_value_case)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-header-value-case.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-header-value-case.creq"));
}


TEST(createCanonicalRequest,post_vanilla)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-vanilla.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-vanilla.creq"));
}


TEST(createCanonicalRequest,post_vanilla_empty_query_value)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-vanilla-empty-query-value.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-vanilla-empty-query-value.creq"));
}


TEST(createCanonicalRequest,post_vanilla_query)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-vanilla-query.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-vanilla-query.creq"));
}


TEST(createCanonicalRequest,post_x_www_form_urlencoded)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-x-www-form-urlencoded.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded.creq"));
}


TEST(createCanonicalRequest,post_x_www_form_urlencoded_parameters)
{
    std::string canonical_request = GetCreateCanonicalRequest("cm_testsuite/post-x-www-form-urlencoded-parameters.req");

    ASSERT_EQ(canonical_request, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded-parameters.creq"));
}

// Task 2: Create a String to Sign for Signature Version 4
TEST(createStringToSign, get_header_key_duplicate)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-header-key-duplicate.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-header-key-duplicate.sts"));
}


TEST(createStringToSign, get_header_value_order)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-header-value-order.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-header-value-order.sts"));
}


TEST(createStringToSign, get_header_value_trim)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-header-value-trim.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-header-value-trim.sts"));
}


TEST(createStringToSign, get_relative)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-relative.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-relative.sts"));
}


TEST(createStringToSign, get_relative_relative)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-relative-relative.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-relative-relative.sts"));
}


TEST(createStringToSign, get_slash)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-slash.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-slash.sts"));
}


TEST(createStringToSign, get_slash_dot_slash)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-slash-dot-slash.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-slash-dot-slash.sts"));
}


TEST(createStringToSign, get_slashes)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-slashes.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-slashes.sts"));
}


TEST(createStringToSign, get_slash_pointless_dot)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-slash-pointless-dot.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-slash-pointless-dot.sts"));
}


TEST(createStringToSign, get_space)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-space.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-space.sts"));
}


TEST(createStringToSign, get_unreserved)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-unreserved.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-unreserved.sts"));
}


TEST(createStringToSign, get_utf8)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-utf8.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-utf8.sts"));
}


TEST(createStringToSign, get_vanilla)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla.sts"));
}


TEST(createStringToSign, get_vanilla_empty_query_key)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-empty-query-key.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-empty-query-key.sts"));
}


TEST(createStringToSign, get_vanilla_query)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-query.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-query.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_key)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-query-order-key.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-query-order-key.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_key_case)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-query-order-key-case.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-query-order-key-case.sts"));
}


TEST(createStringToSign, get_vanilla_query_order_value)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-query-order-value.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-query-order-value.sts"));
}


TEST(createStringToSign, get_vanilla_query_unreserved)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-query-unreserved.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-query-unreserved.sts"));
}


TEST(createStringToSign, get_vanilla_ut8_query)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/get-vanilla-ut8-query.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/get-vanilla-ut8-query.sts"));
}


TEST(createStringToSign, post_header_key_case)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-header-key-case.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-header-key-case.sts"));
}


TEST(createStringToSign, post_header_key_sort)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-header-key-sort.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-header-key-sort.sts"));
}


TEST(createStringToSign, post_header_value_case)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-header-value-case.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-header-value-case.sts"));
}


TEST(createStringToSign, post_vanilla)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-vanilla.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-vanilla.sts"));
}


TEST(createStringToSign, post_vanilla_empty_query_value)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-vanilla-empty-query-value.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-vanilla-empty-query-value.sts"));
}


TEST(createStringToSign, post_vanilla_query)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-vanilla-query.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-vanilla-query.sts"));
}


TEST(createStringToSign, post_vanilla_query_nonunreserved)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-vanilla-query-nonunreserved.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-vanilla-query-nonunreserved.sts"));
}


TEST(createStringToSign, post_vanilla_query_space)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-vanilla-query-space.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-vanilla-query-space.sts"));
}


TEST(createStringToSign, post_x_www_form_urlencoded)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-x-www-form-urlencoded.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded.sts"));
}


TEST(createStringToSign, post_x_www_form_urlencoded_parameters)
{
    std::string string_to_sign = GetCreateStringToSign("cm_testsuite/post-x-www-form-urlencoded-parameters.creq");

    ASSERT_EQ(string_to_sign, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded-parameters.sts"));
}

// Task 3:  Calculate the AWS Signature Version 4

TEST(createAuthorizationHeader, get_header_key_duplicate)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-header-key-duplicate.req", "cm_testsuite/get-header-key-duplicate.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-header-key-duplicate.authz"));
}

TEST(createAuthorizationHeader, get_header_value_order)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-header-value-order.req", "cm_testsuite/get-header-value-order.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-header-value-order.authz"));
}


TEST(createAuthorizationHeader, get_header_value_trim)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-header-value-trim.req", "cm_testsuite/get-header-value-trim.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-header-value-trim.authz"));
}


TEST(createAuthorizationHeader, get_vanilla)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla.req", "cm_testsuite/get-vanilla.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_empty_query_key)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-empty-query-key.req", "cm_testsuite/get-vanilla-empty-query-key.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-empty-query-key.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-query.req", "cm_testsuite/get-vanilla-query.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-query.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_key)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-query-order-key.req", "cm_testsuite/get-vanilla-query-order-key.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-query-order-key.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_key_case)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-query-order-key-case.req", "cm_testsuite/get-vanilla-query-order-key-case.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-query-order-key-case.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_order_value)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-query-order-value.req", "cm_testsuite/get-vanilla-query-order-value.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-query-order-value.authz"));
}


TEST(createAuthorizationHeader, get_vanilla_query_unreserved)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/get-vanilla-query-unreserved.req", "cm_testsuite/get-vanilla-query-unreserved.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/get-vanilla-query-unreserved.authz"));
}


TEST(createAuthorizationHeader, post_header_key_case)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-header-key-case.req", "cm_testsuite/post-header-key-case.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-header-key-case.authz"));
}


TEST(createAuthorizationHeader, post_header_key_sort)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-header-key-sort.req", "cm_testsuite/post-header-key-sort.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-header-key-sort.authz"));
}


TEST(createAuthorizationHeader, post_header_value_case)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-header-value-case.req", "cm_testsuite/post-header-value-case.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-header-value-case.authz"));
}


TEST(createAuthorizationHeader, post_vanilla)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-vanilla.req", "cm_testsuite/post-vanilla.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-vanilla.authz"));
}


TEST(createAuthorizationHeader, post_vanilla_empty_query_value)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-vanilla-empty-query-value.req", "cm_testsuite/post-vanilla-empty-query-value.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-vanilla-empty-query-value.authz"));
}


TEST(createAuthorizationHeader, post_vanilla_query)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-vanilla-query.req", "cm_testsuite/post-vanilla-query.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-vanilla-query.authz"));
}


TEST(createAuthorizationHeader, post_x_www_form_urlencoded)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-x-www-form-urlencoded.req", "cm_testsuite/post-x-www-form-urlencoded.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded.authz"));
}


TEST(createAuthorizationHeader, post_x_www_form_urlencoded_parameters)
{
    std::string authorization_header = GetAuthorizationHeader("cm_testsuite/post-x-www-form-urlencoded-parameters.req", "cm_testsuite/post-x-www-form-urlencoded-parameters.sts");

    ASSERT_EQ(authorization_header, GetWholeFile("cm_testsuite/post-x-www-form-urlencoded-parameters.authz"));
}


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    std::string bin_path;
    assert(get_running_binary_path(bin_path));
    Poco::Path p_bin_path(bin_path);
    test_path = p_bin_path.parent().toString();
    cout << "test directory:" << test_path << endl;

    return RUN_ALL_TESTS();
}
