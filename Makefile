HEADER = $(wildcard *.h)
SOURCE = $(wildcard *.c)
OBJECT = $(patsubst %.c, %.o, $(SOURCE))
BINARY = kcptun-libev

EXTERNAL_HEADER = $(wildcard kcp/*.h) $(wildcard json/*.h)
EXTERNAL_SOURCE = $(wildcard kcp/*.c) $(wildcard json/*.c)
EXTERNAL_OBJECT = $(patsubst %.c, %.o, $(EXTERNAL_SOURCE))

MODULE_CFLAGS = -std=c11 -pedantic -Wall -Wextra -Werror
MODULE_CFLAGS += -D_POSIX_C_SOURCE=199309L

.PHONY: all
all: release

.PHONY: native
native: CFLAGS += -march=native -mtune=native
native: release

.PHONY: release
release: CFLAGS += -O2 -g -DNDEBUG
release: LDFLAGS += -lev -lsodium -lm -lpthread
release: $(BINARY)

.PHONY: sanitize
sanitize: CFLAGS += -O1 -ggdb3 -gdwarf-2
sanitize: CFLAGS += -fsanitize=address,leak,undefined
sanitize: LDFLAGS += -fsanitize=address,leak,undefined
sanitize: LDFLAGS += -lev -lsodium -lm -lpthread
sanitize: $(BINARY)

.PHONY: mingw64
mingw64: CFLAGS += -D__MINGW32__ -D__MINGW64__ -I/mingw64/include
mingw64: LDFLAGS += -L/mingw64/lib -static
mingw64: release

.PHONY: debug
debug: CFLAGS += -O0 -ggdb3 -gdwarf-2
debug: LDFLAGS += -lev -lsodium -lm -lpthread
debug: LDFLAGS += -static
debug: $(BINARY)

.PHONY: install
install: $(BINARY)
	install $(BINARY) /usr/local/bin

.PHONY: uninstall
uninstall:
	rm -f /usr/local/bin/$(BINARY)

.PHONY: clean
clean:
	rm -f $(BINARY) $(OBJECT) $(EXTERNAL_OBJECT)

.PHONY: tidy
tidy: $(SOURCE) $(HEADER)
	clang-tidy $(SOURCE) $(HEADER) -checks=* -- -std=c11

$(BINARY): $(OBJECT) $(EXTERNAL_OBJECT)
	$(CROSS_COMPILE)$(CC) $(OBJECT) $(EXTERNAL_OBJECT) $(LDFLAGS) -o $@

%.o: %.c $(HEADER) $(MAKEFILE_LIST)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $(MODULE_CFLAGS) -c $< -o $@

$(EXTERNAL_OBJECT): %.o: %.c $(EXTERNAL_HEADER)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $< -o $@
