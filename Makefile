CXX=g++
CC=gcc
AS=as
AR=ar
LD=ld
FLAGS:=-I/usr/local/include -std=c++11 -Wall -g -fPIC -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -fopenmp
LIB_PATH=-L/usr/local/lib/
LIBS=$(LIB_PATH) -lPocoFoundation -lPocoNet -lPocoUtil -lPocoCrypto -lPocoNetSSL -lPocoXML -lPocoJSON -ljson -lssl -lcrypto -lcurl -lpcap
INC=./

TESTS=tests/test_awsClient
TST_AWSCLIENT_OBJ=tests/test_awsClient.o awssigv4.o awsClient.o
TST_AWSV4_OBJ=tests/test_awssigv4.o awssigv4.o
TST_CMIOS3RET_OBJ=tests/test_awsClient_mock_retry.o awssigv4.o

#.PHONY : clean all
.DEFAULT_GOAL := all
.PHONY : clean check all

all: libawsClient test_awsClient test_awssigv4 test_awsClient_mock_retry

-include $(OBJS:.o=.d)

%.o: %.cpp
	$(CXX) -c $(FLAGS) $*.cpp -o $*.o
	$(CXX) -MM $(FLAGS) $*.cpp > $*.d

%.gtest: %.cpp
	$(CXX) -DGTEST -c $(FLAGS) -I$(INC) $*.cpp -o $*_gtest.o
	$(CXX) -MM $(FLAGS) -I$(INC) $*.cpp > $*_gtest.d

test_awsClient: $(TST_AWSCLIENT_OBJ)
	$(CXX) -o tests/test_awsClient $(TST_AWSCLIENT_OBJ) -pedantic $(FLAGS) $(LIBS)

test_awssigv4: $(TST_AWSV4_OBJ)
	$(CXX) -o tests/test_awssigv4 $(TST_AWSV4_OBJ) -pedantic $(FLAGS) -I$(INC) $(LIBS) -lgtest -lgmock -lpthread

test_awsClient_mock_retry: $(TST_CMIOS3RET_OBJ) awsClient.gtest
	$(CXX) -o tests/test_awsClient_mock_retry $(TST_CMIOS3RET_OBJ) awsClient_gtest.o -pedantic $(FLAGS) -I$(INC) $(LIBS) -lgtest -lgmock -lpthread

libawsClient: awssigv4.o awsClient.o
	$(CXX) -shared -o $@.so $^ $(LIBS)

clean:
	$(RM) *.o *.d *.so tests/*.o tests/*.d $(TESTS) tests/test_awsClient_mock_retry tests/test_awssigv4
