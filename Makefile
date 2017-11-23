CXX=g++
CC=gcc
AS=as
AR=ar
LD=ld
FLAGS:=-I/usr/local/include -std=c++11 -Wall -g -fPIC -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -fopenmp 
LIB_PATH=-L/usr/local/lib/
LIBS=$(LIB_PATH) -lPocoFoundation -lPocoNet -lPocoUtil -lPocoCrypto -lPocoNetSSL -lPocoXML -lPocoJSON -ljson -lssl -lcrypto -lcurl -lpcap

TESTS=tests/test_awsClient
TST_AWSCLIENT_OBJ=tests/test_awsClient.o awssigv4.o awsClient.o

#.PHONY : clean all
.DEFAULT_GOAL := all
.PHONY : clean check all

all: libawsClient test_awsClient

-include $(OBJS:.o=.d)

%.o: %.cpp
	$(CXX) -c $(FLAGS) -I$(INC) $*.cpp -o $*.o
	$(CXX) -MM $(FLAGS) -I$(INC) $*.cpp > $*.d

test_awsClient: $(TST_AWSCLIENT_OBJ)
	$(CXX) -o tests/test_awsClient $(TST_AWSCLIENT_OBJ) -pedantic $(FLAGS) $(LIBS)

libawsClient: awssigv4.o awsClient.o
	$(CXX) -shared -o $@.so $^ $(LIBS)

clean:
	$(RM) *.o *.d *.so tests/*.o tests/*.d $(TESTS)
	find . -type f \( -name '*.gcda' -o -name '*.gcno' \) -delete
