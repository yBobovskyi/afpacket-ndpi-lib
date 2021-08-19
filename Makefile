NAME :=		ndpi-afpacket-lib

SRCS :=		src/ndpi-afpacket-process.c

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

CPPFLAGS +=	-I/home/yevhen/ndpi-lib/include

# This needs to point to the nDPI include directory.
CPPFLAGS += -I/home/yevhen/nDPI/src/include

all:
	$(CC) -fPIC $(CPPFLAGS) -o $(NAME).so -shared $(SRCS) $(LDLIBS)

clean:
	rm -f *.so *~

install: ndpi-afpacket-lib.so
	install -d $(PREFIX)/lib/
	install -m 644 npdi-afpacket.so $(PREFIX)/lib/
