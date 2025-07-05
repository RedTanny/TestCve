PROJECT=TestCVE
TEST_CERT_VERIFY=tests/test_cert_verify
CC=gcc
CFLAGS=-Wall -O2
LIBS=-lssl -lcrypto -lcurl

all: $(PROJECT) $(TEST_CERT_VERIFY)

$(PROJECT): main.c
	$(CC) $(CFLAGS) -o $(PROJECT) main.c $(LIBS)

$(TEST_CERT_VERIFY): tests/test_cert_verify.c verify/cert_verify.c
	$(CC) $(CFLAGS) -o $(TEST_CERT_VERIFY) tests/test_cert_verify.c verify/cert_verify.c $(LIBS)

clean:
	rm -f $(PROJECT) $(TEST_CERT_VERIFY) 