CFLAGS += -Wall -g
LDFLAGS += -lssl -lpthread

TESTS = tls

all: $(TESTS)
%: %.c
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)

clean:
	$(RM) $(TESTS)
