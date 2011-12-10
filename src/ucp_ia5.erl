-module(ucp_ia5).
-author('rafal.galczynski@jtendo.com').
-author('adam.rutkowski@jtendo.com').
-export([ascii_to_gsm/1, gsm_to_ascii/1]).
-include("ia5.hrl").

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function converting Ascii Num into IRA Char
%%
%% @spec ascii_to_gsm(Char) -> String
%% @end
%%--------------------------------------------------------------------
ascii_to_gsm(Int) ->
    case lists:keyfind(hex:to_hexstr(Int), 1, ?IA5) of
        {_, Gsm} ->
            list_to_integer(Gsm, 16);
        false ->
            Int
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function converting IRA HexStr into CharStr
%%
%% @spec gsm_to_ascii(Char) -> String
%% @end
%%--------------------------------------------------------------------
gsm_to_ascii(HexStr) ->
    case lists:keyfind(string:to_upper(HexStr), 2, ?IA5) of
        {Ascii, _} ->
            Ascii;
        false ->
            HexStr
    end.


