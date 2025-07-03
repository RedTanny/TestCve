PROJECT=TestCVE
CC=gcc
CFLAGS=-Wall -O2
LIBS=-lssl -lcrypto -lcurl

all: $(PROJECT)

$(PROJECT): main.c
	$(CC) $(CFLAGS) -o $(PROJECT) main.c $(LIBS)

clean:
	rm -f $(PROJECT) 