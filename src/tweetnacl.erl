%% Copyright (c) 2016 Ulf Leopold.
-module(tweetnacl).

-export([keypair/0]).
-export([encrypt/3]).
-export([decrypt/3]).

-include("tweetnacl.hrl").

%% Keeping the message size below 30k, keeps enc/dec times below 1ms (on
%% my hardware). If you remove this limit you may see degraded
%% responsiveness of the Erlang VM.
-define(MAX_MESSAGE_SIZE, 30 * 1024).

keypair() ->
  Res = tweetnacl_nifs:crypto_box_keypair(),
  case Res of
    {0, Pk, Sk}    -> {Pk, Sk};
    {Rc, _Pk, _Sk} -> {tweetnacl_error, Rc}
  end.

encrypt(Message, Pk, Sk) ->
  true = byte_size(Message) =< ?MAX_MESSAGE_SIZE,
  Len = ?ZEROBYTES + byte_size(Message),
  ZeroPaddedMsg = <<0:(?ZEROBYTES * 8), Message/binary>>,
  Nonce = tweetnacl_nifs:nonce(),
  erlang:yield(),
  Res = tweetnacl_nifs:crypto_box(ZeroPaddedMsg, Len, Nonce, Pk, Sk),
  erlang:yield(),
  case Res of
    {0, ResultData} ->
      <<0:(?BOXZEROBYTES * 8), Encrypted/binary>> = ResultData,
      <<Nonce/binary, Encrypted/binary>>;
    {Rc, _ResultData} -> {tweetnacl_error, Rc}
  end.

decrypt(NonceAndEncrypted, Pk, Sk) ->
  true = byte_size(NonceAndEncrypted) =< (?MAX_MESSAGE_SIZE + ?NONCEBYTES +
                                            ?BOXZEROBYTES),
  <<Nonce:?NONCEBYTES/binary, Encrypted/binary>> = NonceAndEncrypted,
  ZeroPaddedEncrypted = <<0:(?BOXZEROBYTES * 8), Encrypted/binary>>,
  Res = tweetnacl_nifs:crypto_box_open(ZeroPaddedEncrypted,
                                       byte_size(ZeroPaddedEncrypted),
                                       Nonce, Pk, Sk),
  erlang:yield(),
  case Res of
    {0, ResultData} ->
      <<0:(?ZEROBYTES * 8), Plaintext/binary>> = ResultData,
      Plaintext;
    {Rc, _ResultData} -> {tweetnacl_error, Rc}
  end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
enc_dec_test() ->
  {SenderPk, SenderSk} = keypair(),
  {ReceiverPk, ReceiverSk} = keypair(),
  M = crypto:rand_bytes(10 * 1024),
  E = encrypt(M, ReceiverPk, SenderSk),
  ?assertEqual(M, decrypt(E, SenderPk, ReceiverSk)).

perf_test() ->
  measure(<<"hello">>),
  measure(crypto:rand_bytes(30 * 1024)).

measure(M) ->
  {SenderPk, SenderSk} = keypair(),
  {ReceiverPk, ReceiverSk} = keypair(),
  T1 = avg(fun() -> encrypt(M, ReceiverPk, SenderSk) end, 100),
  E = encrypt(M, ReceiverPk, SenderSk),
  T2 = avg(fun() -> decrypt(E, SenderPk, ReceiverSk) end, 100),
  ?debugFmt("Avg. encryption (~p byte msg) time: ~pms~n", [byte_size(M), T1]),
  ?debugFmt("Avg. decryption (~p byte msg) time: ~pms~n", [byte_size(M), T2]).

avg(Fun, N) ->
  R = lists:map(fun(_) -> {T, _} = timer:tc(Fun), T end, lists:seq(1, N)),
  lists:sum(R) / N.

-endif.
