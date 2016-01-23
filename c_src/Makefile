all:
	mkdir -p ../priv
	gcc -O3 tweetnacl_nifs.c tweetnacl.c -o ../priv/tweetnacl_nifs.so -fPIC \
	-shared -I ${ERTS_INCLUDE_DIR} -L ${ERL_INTERFACE_LIB_DIR} \
	-lerl_interface -lei

clean:
	rm -f nifs.o ../priv/nifs.so

include env.mk
