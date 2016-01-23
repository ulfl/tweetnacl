TweetNaCl for Erlang
====================

This library is an Erlang interface to the TweetNaCl cryptographic
functions. It is meant to encrypt/decrypt small messages (< 30k) and
not bulk data.

The design goals for this project are:

 * Keep the implementation as minimal and simple as possible to allow
   for easy security review.

 * Prioritize simplicity and robustness over performance.
 
 * Focus on supporting enc/dec for small messages.

 * Focus on UNIX systems.

 * Support for Erlang runtime code upgrades is not a priority.

In order to execute as regular NIFs, without degrading Erlang VM
scheduler performance, the maximum message size for encryption /
decryption has been capped at 30k. This to keep the execution time
below 1ms (see http://erlang.org/doc/man/erl_nif.html).

Note that this library is currently work in progress.

Copyright (c) 2016 Ulf Leopold.
