-module(hex).

-export([to_hexstr/1,
         hexstr_to_bin/1,
         hexstr_to_list/1]).

to_hexstr(Bin) when is_binary(Bin) ->
    [to_hexstr(X) || X <- binary_to_list(Bin)];

to_hexstr(Int) when is_integer(Int) andalso Int =< 255 ->
    string:right(integer_to_list(Int, 16), 2, $0);

to_hexstr(Int) when is_integer(Int) ->
    string:right(integer_to_list(Int, 16), 4, $0);

to_hexstr(L) when is_list(L) ->
    [to_hexstr(X) || X <- L].

hexstr_to_bin(H) ->
    <<<<(erlang:list_to_integer([X], 16)):4>> || X <- H>>.

hexstr_to_list(H) ->
    binary_to_list(hexstr_to_bin(H)).
