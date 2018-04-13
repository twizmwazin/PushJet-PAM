CC = gcc
CCFLAGS = -c -fpic
LDFLAGS = -shared
LIBS = -lconfig -lcurl -lpam

SRCS = pam_pushjet.c
OBJS = $(SRCS:.c=.o)
BINS = pam_pushjet.so

all: $(BINS)

pam_pushjet.so: $(OBJS)
	$(CC) $(LDFLAGS) $(LIBS) $(OBJS) -o pam_pushjet.so

%.o: %.c
	$(CC) $(CCFLAGS) $<

install: pam_pushjet.so
	cp pam_pushjet.so /lib/security/pam_pushjet.so
	chmod 755 /lib/security/pam_pushjet.so
	chown root /lib/security/pam_pushjet.so

clean:
	rm *.o
	rm *.so

.PHONY: clean install

