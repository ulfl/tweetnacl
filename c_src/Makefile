UNAME := $(shell uname -s)

CFLAGS =

ifeq ($(UNAME),Darwin)
CFLAGS += -flat_namespace -undefined suppress
endif

all:
	mkdir -p ../priv
	gcc -O3 $(CFLAGS) tweetnacl_nifs.c tweetnacl.c -o ../priv/tweetnacl_nifs.so -fPIC \
	-shared -I ${ERTS_INCLUDE_DIR} -L ${ERL_INTERFACE_LIB_DIR} \
	-lerl_interface -lei

clean:
	rm -f nifs.o ../priv/nifs.so

include env.mk
