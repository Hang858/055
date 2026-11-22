CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -fPIC -std=c11 -Wall -Wextra -Iinclude
GOCACHE ?= $(CURDIR)/.gocache
SRC     := pq_registry.c pq_placeholder.c pq_bit_placeholder.c
OBJ     := $(SRC:.c=.o)
LIB     := lib/libpqalg.a

.PHONY: all lib test vendor clean
all: lib

lib: $(LIB)

$(LIB): $(OBJ)
	@mkdir -p lib
	$(AR) rcs $@ $(OBJ)

%.o: %.c include/pq_alg.h
	$(CC) $(CFLAGS) -c $< -o $@

vendor:
	cd vendor && ./build.sh

test: vendor
	GOCACHE=$(GOCACHE) CGO_ENABLED=1 GOTOOLCHAIN=local \
	  LIGHTLATTICE_LIBDIR=$(CURDIR)/vendor/lib go test ./...

clean:
	rm -f $(OBJ) $(LIB)
	rm -rf lib
