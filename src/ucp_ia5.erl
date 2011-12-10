-module(ucp_ia5).
-author('rafal.galczynski@jtendo.com').
-author('adam.rutkowski@jtendo.com').
-export([ascii_to_gsm/1, gsm_to_ascii/1]).
-include("ia5.hrl").


-spec ascii_to_gsm(integer()) -> integer().

%%--------------------------------------------------------------------
%% @doc
%% Function converting ascii integer code into IRA code
%% @end
%%--------------------------------------------------------------------
ascii_to_gsm(Int) when is_integer(Int) ->
    case lists:keyfind(hex:to_hexstr(Int), 1, ?IA5) of
        {_, Gsm} ->
            list_to_integer(Gsm, 16);
        false ->
            Int
    end.


-spec gsm_to_ascii(string()) -> string().

%%--------------------------------------------------------------------
%% @doc
%% Function converting IRA octet into corresponding ascii value
%% @end
%%--------------------------------------------------------------------
gsm_to_ascii(HexStr) when is_list(HexStr) ->
    case lists:keyfind(string:to_upper(HexStr), 2, ?IA5) of
        {Ascii, _} ->
            Ascii;
        false ->
            HexStr
    end.


