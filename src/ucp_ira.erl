-module(ucp_ira).
-author('adam.rutkowski@jtendo.com').
-export([to/2]).
-include("ira.hrl").

to(ira, Char) when is_integer(Char) ->
    case lists:keyfind(Char, 1, ?IRA) of
        {_, Ira} -> Ira;
        false -> Char
    end;
to(ascii, Char) when is_integer(Char) ->
    case lists:keyfind(Char, 2, ?IRA) of
        {Ascii, _} -> Ascii;
        false -> Char
    end;
to(Type, Str) when is_atom(Type), is_list(Str) ->
    lists:foldl(fun(Char, Acc) ->
                Acc ++ [to(Type, Char)]
        end, "", Str).



