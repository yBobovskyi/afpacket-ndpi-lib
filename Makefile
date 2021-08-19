NAME :=		libndpi-afpacket

SRCS :=		src/ndpi-afpacket-process.c

CPPFLAGS +=	-I/home/yevhen/ndpi-lib/include

# This needs to point to the nDPI include directory.
CPPFLAGS += -I/home/yevhen/nDPI/src/include

LDLIBS += -lndpi

all:
	$(CC) -fPIC $(CPPFLAGS) -o $(NAME).so -shared $(SRCS) $(LDLIBS)

clean:
	rm -f *.so *~

install: libndpi-afpacket.so
	install -d /usr/lib/
	install -m 644 libndpi-afpacket.so /usr/lib/
