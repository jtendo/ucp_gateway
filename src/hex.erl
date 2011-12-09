-module(hex).
-author('andrzej.trawinski@jtendo.com').

-export([to_hexstr/1,
         hexstr_to_bin/1,
         hexstr_to_list/1]).

to_hexstr(Bin) when is_binary(Bin) ->
    to_hexstr(binary_to_list(Bin));

to_hexstr(Int) when is_integer(Int) andalso Int > 255 ->
    to_hexstr(unicode, Int);

to_hexstr(Int) when is_integer(Int) ->
    to_hexstr(ascii, Int);

to_hexstr(L) when is_list(L) ->
    Type = case lists:any(fun(X) when X > 255 ->
                    true;
                   (_) ->
                    false
                   end, L) of
              true -> unicode;
              false -> ascii
          end,
    lists:flatten([to_hexstr(Type, X) || X <- L]).

hexstr_to_bin(H) ->
    <<<<(erlang:list_to_integer([X], 16)):4>> || X <- H>>.

hexstr_to_list(H) ->
    binary_to_list(hexstr_to_bin(H)).

to_hexstr(ascii, Int) ->
    string:right(integer_to_list(Int, 16), 2, $0);

to_hexstr(unicode, Int) ->
    string:right(integer_to_list(Int, 16), 4, $0).

