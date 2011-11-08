-module(ucp_ia5).
-author('rafal.galczynski@jtendo.com').
-export([ascii_to_gsm/1, gsm_to_ascii/1]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function converting Ascii Num into IRA Char
%%
%% @spec ascii_to_gsm(Char) -> String
%% @end
%%--------------------------------------------------------------------
ascii_to_gsm(Int) ->
    case lists:keyfind(hex:to_hexstr(Int), 1, ia5_alphabet()) of
        {_, Gsm} ->
            http_util:hexlist_to_integer(Gsm);
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
    case lists:keyfind(string:to_upper(HexStr),1,
            lists:map(fun({X,Y}) -> {Y,X} end, ia5_alphabet())) of
        {_,Ascii} ->
            Ascii;
        false ->
            HexStr
    end.

ia5_alphabet() ->
    [{"40","00"},
     {"A3","01"},
     {"24","02"},
     {"A5","03"},
     {"E8","04"},
     {"E9","05"},
     {"F9","06"},
     {"EC","07"},
     {"F2","08"},
     {"C7","09"},
     {"D8","0B"},
     {"F8","0C"},
     {"C5","0E"},
     {"E5","0F"},
     {"5F","11"},
     {"A4","24"},
     {"A1","40"},
     {"C4","5B"},
     {"D6","5C"},
     {"D1","5D"},
     {"DC","5E"},
     {"A7","5F"},
     {"BF","60"},
     {"E4","7B"},
     {"F6","7C"},
     {"F1","7D"},
     {"FC","7E"},
     {"E0","7F"},

     {"0C","0A"},
     {"5E","73"},
     {"7B","28"},
     {"7D","29"},
     {"5C","2F"},
     {"5B","3C"},
     {"7E","3D"},
     {"5D","3E"},
     {"7C","40"},
     {"AC","65"}].

