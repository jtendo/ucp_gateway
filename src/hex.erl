-module(hex).

-export([bin_to_hexstr/1,
         int_to_hexstr/1,
         list_to_hexstr/1,
         to_hexstr/1]).


bin_to_hexstr(X) -> to_hexstr(X).
int_to_hexstr(X) -> to_hexstr(X).
list_to_hexstr(X) -> to_hexstr(X).

to_hexstr(Bin) when is_binary(Bin) ->
    [to_hexstr(X) || X <- binary_to_list(Bin)];

to_hexstr(Int) when is_integer(Int) andalso Int =< 255 ->
    string:right(integer_to_list(Int, 16), 2, $0);

to_hexstr(Int) when is_integer(Int) ->
    string:right(integer_to_list(Int, 16), 4, $0);

to_hexstr(L) when is_list(L) ->
    [to_hexstr(X) || X <- L].

% list_to_integer("F", 16).
