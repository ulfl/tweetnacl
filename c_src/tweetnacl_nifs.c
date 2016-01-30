// Copyright (c) 2016 Ulf Leopold.
#include <unistd.h>
#include <fcntl.h>

#include "erl_nif.h"
#include "tweetnacl.h"

typedef unsigned char U8;

void randombytes(unsigned char buffer[], unsigned long long size);

static ERL_NIF_TERM nif_crypto_box_keypair(ErlNifEnv* env, int argc,
                                           const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM pk, sk;
    U8 *pk_data, *sk_data;
    int rc;

    pk_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pk);
    sk_data = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &sk);
    rc = crypto_box_keypair(pk_data, sk_data);
    return enif_make_tuple3(env, enif_make_int(env, rc), pk, sk);
}

// Return a nonce of the standard size.
static ERL_NIF_TERM nif_nounce(ErlNifEnv* env, int argc,
                               const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM nonce;
    U8* data;

    data = enif_make_new_binary(env, crypto_box_NONCEBYTES, &nonce);
    randombytes(data, crypto_box_NONCEBYTES);
    return nonce;
}

static ERL_NIF_TERM nif_crypto_box(ErlNifEnv* env, int argc,
                                   const ERL_NIF_TERM argv[])
{
    unsigned int len;
    ErlNifBinary message, nonce, pk, sk;
    ERL_NIF_TERM encrypted;
    U8* encrypted_data;
    int rc;
    
    if (!enif_get_uint(env, argv[1], &len)) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[0], &message) || message.size != len) {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[2], &nonce) ||
        nonce.size != crypto_box_NONCEBYTES)
    {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[3], &pk) ||
        pk.size != crypto_box_PUBLICKEYBYTES)
    {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[4], &sk) ||
        sk.size != crypto_box_SECRETKEYBYTES)
    {
       return enif_make_badarg(env);
    }

    encrypted_data = enif_make_new_binary(env, len, &encrypted);

    rc = crypto_box(encrypted_data, message.data, len, nonce.data, pk.data,
                    sk.data);

    return enif_make_tuple2(env, enif_make_int(env, rc), encrypted);
}

static ERL_NIF_TERM nif_crypto_box_open(ErlNifEnv* env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    unsigned int len;
    ErlNifBinary encrypted, nonce, pk, sk;
    ERL_NIF_TERM plain;
    U8* data;
    int rc;

    if (!enif_get_uint(env, argv[1], &len)) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[0], &encrypted) ||
        encrypted.size != len)
    {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[2], &nonce) ||
        nonce.size != crypto_box_NONCEBYTES)
    {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[3], &pk) ||
        pk.size != crypto_box_PUBLICKEYBYTES)
    {
       return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[4], &sk) ||
        sk.size != crypto_box_SECRETKEYBYTES)
    {
       return enif_make_badarg(env);
    }

    data = enif_make_new_binary(env, len, &plain);
    
    rc = crypto_box_open(data, encrypted.data, len, nonce.data, pk.data,
                         sk.data);

    return enif_make_tuple2(env, enif_make_int(env, rc), plain);
}

// Not using enif_alloc for the priv_data since randombytes() has a
// fixed signature and we can't call enif_priv_data(env) inside
// it. Instead use a static. Also, regarding /dev/urandom, see
// https://news.ycombinator.com/item?id=7301398.
static int file = 0;
int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    file = open("/dev/urandom", O_RDONLY);
    if (file < 0) { return -1; }
    return 0;
}

void unload(ErlNifEnv* env, void* priv_data) {
    close(file);
}

static ErlNifFunc nif_funcs[] = {
    {"nonce", 0, nif_nounce},
    {"crypto_box_keypair", 0, nif_crypto_box_keypair},
    {"crypto_box", 5, nif_crypto_box},
    {"crypto_box_open", 5, nif_crypto_box_open}
};

ERL_NIF_INIT(tweetnacl_nifs, nif_funcs, load, NULL, NULL, unload)

void randombytes(unsigned char buffer[], unsigned long long size) {
    int i;
    while (size > 0) {
        i = read(file, buffer, size);
        if (i < 1) { continue; }
        buffer += i;
        size -= i;
    }
}
