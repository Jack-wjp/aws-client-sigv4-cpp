# aws-client-sigv4-cpp
# Rest API for AWS S3 using signature version 4

#C++ implementation of AWS Signatrue V4 for signing API request
#C++ implementation of Client for AWS S3 using AWS Signatrue V4 API requests

To run the test cases following parameters needs to be configured.
Region needs to be configured to run the test i.e.: ap-south-1
Secret Key needs to be configured to run the test i.e.: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Key prefix needs to be configured to run the test i.e.: /example_test/
Access key needs to be configured to run the test i.e. : AKIAIOSFODNN7EXAMPLE
Bucket name needs to be configured to run the test i.e. : example_bucket

directory structure on s3 that is required to run the test cases

# bucket name : example_bucket
inside the bucket the following files needs to be created.
/example_test/test_500_mb_file.bin
/example_test/test_100_mb_file.bin
/example_test/test.pdf
/example_test/test_pic.png
/example_test/cpp_test
/example_test/test_dir/test_dir
/example_test/test_dir/test_dir/file1.txt
/example_test/test_dir/test_dir/file2.txt
/example_test/test_dir/test_file1.txt
/example_test/test_dir/test_file2.txt
/example_test/test_dir/test_file3.txt

 # To run test cases

 0. test_500_mb_file.bin needs to be created which should be around 500 MB.
 1. test_100_mb_file.bin needs to be created which should be around 100 MB.
 2. test_pic.png needs to be created which should be around 50 MB.
 3. No special care required.
 4. No special care required.
 5. a file name test.pdf needs to be present whose md5 sum must be known apriory.
 6. No special care required.
 7. file cpp_test needs to be created.
 8. No special care required.
 9. test_dir/test_dir and a few files needs to be created.
 10. test_dir and a few files needs to be created and make sure test only scans the file.
 11. No special care required.
 12. No special care required.
