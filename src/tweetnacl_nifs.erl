%% Copyright (c) 2016 Ulf Leopold.
-module(tweetnacl_nifs).

-export([crypto_box_keypair/0]).
-export([nonce/0]).
-export([crypto_box/5]).
-export([crypto_box_open/5]).

-on_load(init/0).

-include("tweetnacl.hrl").

-type pk()    :: <<_:?PUBLICKEYBYTES, _:_*8>>.
-type sk()    :: <<_:?SECRETKEYBYTES, _:_*8>>.
-type nonce() :: <<_:?NONCEBYTES, _:_*8>>.

init() ->
  Dir = case code:priv_dir(tweetnacl) of
          {error, bad_name} -> "./priv/"; %% For Eunit.
          X                 -> X
        end,
  ok = erlang:load_nif(filename:join([Dir, "tweetnacl_nifs"]), 0).

-spec crypto_box_keypair() -> {integer(), binary(), binary()}.
crypto_box_keypair() -> erlang:nif_error("TweetNaCl: NIF library not loaded").

-spec nonce() -> binary().
nonce() -> erlang:nif_error("TweetNaCl: tweetnacl_nifs.so not loaded").

-spec crypto_box(binary(), integer(), nonce(), pk(), sk()) ->
                    {integer(), binary()}.
crypto_box(_Plain, _Length, _Nonce, _Pk, _Sk) ->
  erlang:nif_error("TweetNaCl: tweetnacl_nifs.so not loaded").

-spec crypto_box_open(binary(), integer(), nonce(), pk(), sk()) ->
                         {integer(), binary()}.
crypto_box_open(_Encrypted, _Length, _Nonce, _Pk, _Sk) ->
  erlang:nif_error("TweetNaCl: tweetnacl_nifs.so not loaded").
