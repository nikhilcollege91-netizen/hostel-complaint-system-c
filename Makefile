CC=gcc
CFLAGS=-fPIC -O2
LIBNAME=libcomplaints.so

all: $(LIBNAME)

$(LIBNAME): complaints.c complaints.h
	$(CC) $(CFLAGS) -shared -o $(LIBNAME) complaints.c -lsqlite3

clean:
	rm -f $(LIBNAME)