#define GTEST 1
#include "../awsClient.h"
#include "gtest/gtest.h"

using ::testing::AtLeast;
using ::testing::_;
using testing::InSequence;
using namespace hcm;

class S3IOTest: public ::testing::Test
{
    protected:
        const std::string t_host="example_bucket.s3.amazonaws.com";// bucket (example_bucket) needs to be configured to run the test
        const std::string t_service{"s3"};
        const std::string t_region{"ap-south-1"};  // Region needs to be configured to run the test
        const std::string t_prefix = "/example_test/";  // key prefix needs to be configured to run the test
        // below keys are taken from 
        //http://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html
        const std::string t_access_key = "AKIAIOSFODNN7EXAMPLE";  // Access key needs to be configured to run the test
        const std::string t_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // Secre Key needs to be configured to run the test
        MockAWSS3io *aws_s3_io =  nullptr;

        virtual void SetUp()
        {
            aws_s3_io = new MockAWSS3io(t_secret_key, t_access_key, t_service, t_host, t_region, t_prefix);
        }

        //virtual void TearDown()
};

TEST_F(S3IOTest, GetSuccessCase) {
    EXPECT_CALL(*aws_s3_io, get(_,_,_,_,_,_))
        .Times(AtLeast(1));

    AWSio awsio(aws_s3_io, true);
    std::string key="aaa", value="";
    std::map<string, string> resp_hdrs;
    ASSERT_TRUE(OK == awsio.get(key, value, resp_hdrs));
}

TEST_F(S3IOTest, GetFailureCase) {
    int return_val = 500;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, get(_,_,_,_,_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<2>(return_val)).WillRepeatedly(testing::SetArgReferee<2>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc", value="";
    std::map<string, string> resp_hdrs;
    ASSERT_TRUE(OK == awsio.get(key, value, resp_hdrs));
}

TEST_F(S3IOTest, PutSuccessCase) {
    EXPECT_CALL(*aws_s3_io, put(_,_,_))
        .Times(AtLeast(1));

    AWSio awsio(aws_s3_io, true);
    std::string key="aaa", value="putaaa";
    ASSERT_TRUE(OK == awsio.put(key, value));
}

TEST_F(S3IOTest, PutFailureCase) {
    int return_val = 500;
    EXPECT_CALL(*aws_s3_io, put(_,_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<2>(return_val)).WillRepeatedly(testing::SetArgReferee<2>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc", value="putabc";
    ASSERT_TRUE(OK == awsio.put(key, value));
}

TEST_F(S3IOTest, RemoveSuccessCase) {
    EXPECT_CALL(*aws_s3_io, remove(_,_))
        .Times(AtLeast(1));

    AWSio awsio(aws_s3_io, true);
    std::string key="aaa";
    ASSERT_TRUE(OK == awsio.remove(key));
}

TEST_F(S3IOTest, RemoveFailureCase) {
    int return_val = 500;
    EXPECT_CALL(*aws_s3_io, remove(_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<1>(return_val)).WillRepeatedly(testing::SetArgReferee<1>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc";
    ASSERT_TRUE(OK == awsio.remove(key));
}

TEST_F(S3IOTest, HeadSuccessCase) {
    EXPECT_CALL(*aws_s3_io, head(_,_,_,_))
        .Times(AtLeast(1));

    AWSio awsio(aws_s3_io, true);
    std::string key="aaa";
    std::string etag="etag";
    std::string output_value;
    ASSERT_TRUE(OK == awsio.head(key, etag, output_value));
}

TEST_F(S3IOTest, HeadFailureCase) {
    int return_val = 500;
    EXPECT_CALL(*aws_s3_io, head(_,_,_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<3>(return_val)).WillRepeatedly(testing::SetArgReferee<3>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc";
    std::string etag="Etag";
    std::string output_value;
    ASSERT_TRUE(OK == awsio.head(key, etag, output_value));
}

TEST_F(S3IOTest, SCANSuccessCase) {
    EXPECT_CALL(*aws_s3_io, scan(_,_,_,_,_))
        .Times(AtLeast(1));

    AWSio awsio(aws_s3_io, true);
    std::string scanstr="abc", token="", resp_data = "";
    int scan_limit = 1000;
    ASSERT_TRUE(OK == awsio.scan(scanstr, token, resp_data, scan_limit));
}

TEST_F(S3IOTest, SCANFailureCase) {
    int return_val = 500;
    EXPECT_CALL(*aws_s3_io, scan(_,_,_,_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<3>(return_val)).WillRepeatedly(testing::SetArgReferee<3>(200));

    AWSio awsio(aws_s3_io, true);
    std::string scanstr="abc", token="", resp_data = "";
    int scan_limit = 1000;
    ASSERT_TRUE(OK == awsio.scan(scanstr, token, resp_data, scan_limit));
}

TEST_F(S3IOTest, GetFailureCase_520) {
    int return_val = 520;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, get(_,_,_,_,_,_))
        .Times(2).WillRepeatedly(testing::SetArgReferee<2>(return_val));
    EXPECT_CALL(*aws_s3_io, get(_,_,_,_,_,_))
        .WillRepeatedly(testing::SetArgReferee<2>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc", value="";
    std::map<string, string> resp_hdrs;
    ASSERT_TRUE(OK == awsio.get(key, value, resp_hdrs));
}

TEST_F(S3IOTest, PutFailureCase_520) {
    int return_val = 520;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, put(_,_,_))
        .Times(2).WillRepeatedly(testing::SetArgReferee<2>(return_val));
    EXPECT_CALL(*aws_s3_io, put(_,_,_)).WillRepeatedly(testing::SetArgReferee<2>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc", value="putabc";
    ASSERT_TRUE(OK == awsio.put(key, value));
}

TEST_F(S3IOTest, RemoveFailureCase_520) {
    int return_val = 520;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, remove(_,_))
        .Times(2).WillRepeatedly(testing::SetArgReferee<1>(return_val));
    EXPECT_CALL(*aws_s3_io, remove(_,_)).WillRepeatedly(testing::SetArgReferee<1>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc";
    ASSERT_TRUE(OK == awsio.remove(key));
}

TEST_F(S3IOTest, HeadFailureCase_520) {
    int return_val = 520;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, head(_,_,_,_))
        .Times(AtLeast(2)).WillOnce(testing::SetArgReferee<3>(return_val)).WillRepeatedly(testing::SetArgReferee<3>(200));

    AWSio awsio(aws_s3_io, true);
    std::string key="abc";
    std::string etag="Etag";
    std::string output_value;
    ASSERT_TRUE(OK == awsio.head(key, etag, output_value));
}

TEST_F(S3IOTest, SCANFailureCase_520) {
    int return_val = 520;
    InSequence s;
    EXPECT_CALL(*aws_s3_io, scan(_,_,_,_,_))
        .Times(3).WillRepeatedly(testing::SetArgReferee<3>(return_val));
    EXPECT_CALL(*aws_s3_io, scan(_,_,_,_,_)).WillRepeatedly(testing::SetArgReferee<3>(200));

    AWSio awsio(aws_s3_io, true);
    std::string scanstr="abc", token="", resp_data = "";
    int scan_limit = 1000;
    ASSERT_TRUE(OK == awsio.scan(scanstr, token, resp_data, scan_limit));
}

int main(int argc, char** argv) {
  // The following line must be executed to initialize Google Mock
  // (and Google Test) before running the tests.
  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}

