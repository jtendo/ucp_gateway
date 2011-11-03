-module(ucp_utils).
-author('rafal.galczynski@jtendo.com').
-author('andrzej.trawinski@jtendo.com').
-include("ucp_syntax.hrl").
-include("logger.hrl").

-compile([debug_info]).

-export([
         to_ira/1,
         to_7bit/1,
         calculate_sender/1,
         fill_with_zeros/2,
         compose_message/2,
         binary_split/2,
         pad_to/2,
         get_next_trn/1,
         trn_to_str/1,
         decode/1
        ]).

-define(STX,16#02).
-define(ETX,16#03).
-define(MIN_MESSAGE_TRN, 0).
-define(MAX_MESSAGE_TRN, 99).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for converting string to string
%% encoded into IRA, after GSM 03.38 Version 5.3.0
%%
%% @spec to_ira(Str) -> String
%% @end
%%--------------------------------------------------------------------
to_ira(Str) ->
    GsmMessage = lists:map(fun(X) -> ucp_ia5:ascii_to_gsm(X) end, Str),
    lists:flatten(GsmMessage).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for converting string to 7-bit encoding according to:
%% GSM 03.38 Version 5.3.0
%%
%% @spec to_7bit(String) -> String
%% @end
%%--------------------------------------------------------------------
to_7bit(Str) -> binary:bin_to_list(ucp_7bit:to_7bit(Str)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for calculating UCP OAdC field for string and returns list
%% of Hex octets
%%
%% @spec calculate_sender(String) -> {otoa, OTOA, sender, SENDER }
%% @end
%%--------------------------------------------------------------------
calculate_sender(Sender) ->
    case has_only_digits(Sender) of
        true ->
            {otoa, "1139", sender, Sender};
        false ->
            {otoa, "5039", sender, append_length(
                                      hex:list_to_hexstr(
                                        to_7bit(
                                          to_ira(Sender))))}
    end.

%%--------------------------------------------------------------------
%% Function for composing whole ucp message
%%--------------------------------------------------------------------
compose_message(Header, Body) ->
    HF = lists:nthtail(1, tuple_to_list(Header)),
    BF = lists:nthtail(1, tuple_to_list(Body)),
    Len = length(string:join(lists:concat([HF, BF]), "/")) + 3, % 3:for delimiter and CRC
    LenS = string:right(integer_to_list(Len, 10), 5, $0),
    % Update header with proper len value
    NewHeader = Header#ucp_header{len = LenS},
    NHF = lists:nthtail(1, tuple_to_list(NewHeader)),
    % Build message
    Message = string:concat(string:join(lists:concat([NHF, BF]), "/"), "/"),
    CRC = calculate_crc(Message),
    string:concat(Message, CRC).

%%--------------------------------------------------------------------
%% Function for appending list length to biggining of the list
%%--------------------------------------------------------------------
append_length(L) ->
    Fun = fun([H|_]) -> H == $0 end,
    {ElemsWithZero, ElemsWithOutZero} = lists:partition(Fun, L),
    Len = length(ElemsWithOutZero)*2
        + length(ElemsWithZero),
    HexStr = hex:int_to_hexstr(Len),
    lists:flatten([HexStr, L]).

%%--------------------------------------------------------------------
%% Function for getting 8 last significant bits of number
%%--------------------------------------------------------------------
get_8lsb(Integer) ->
    Integer band 255.

%%--------------------------------------------------------------------
%% Function for calculating CRC checksum for UCP Message
%%--------------------------------------------------------------------
calculate_crc(UcpMessage) ->
    string:right(integer_to_list(get_8lsb(lists:sum(Data)), 16), 2, $0),
    hex:int_to_hexstr(
      get_8lsb(
        lists:sum(UcpMessage))).

%%--------------------------------------------------------------------
%% Function for checking if Char is digit
%%--------------------------------------------------------------------
is_digit(C) when C > 46, C < 58  -> true;
is_digit(_) -> false.

%% @private
%% @doc
%% Function for checking if String contains only digits
%%
%% @spec has_only_digits(String) -> true | false
%% @end
%%--------------------------------------------------------------------

has_only_digits(Str) ->
    lists:all(fun(Elem) -> is_digit(Elem) end, Str).



%% @private
%% @doc
%% Function for spliting binary into chunks
%%
%% @spec binary_split(Bin, Size) -> []
%% @end
%%--------------------------------------------------------------------

binary_split(Bin, Size) ->
    case size(Bin) =< Size of
        true ->
            [Bin];
        false ->
            binary_split(Bin, Size, 0, [])
    end.

binary_split(<<>>, _, _, Acc)->
    lists:reverse(Acc);

binary_split(Bin, Size, ChunkNo, Acc)->
    ToProcess = size(Bin) - length(Acc)*Size,
    case ToProcess =< Size of
        true ->
            binary_split(<<>>, Size, ChunkNo+1,
                         [binary:part(Bin, ChunkNo*Size, ToProcess)|Acc]);
        false ->
            binary_split(Bin, Size, ChunkNo+1,
                         [binary:part(Bin, ChunkNo*Size, Size)|Acc])
    end.


pad_to(Width, Binary) ->
     case (Width - size(Binary) rem Width) rem Width
       of 0 -> Binary
        ; N -> <<Binary/binary, 0:(N*8)>>
     end.


get_next_trn(Val) when is_list(Val) ->
    get_next_trn(list_to_integer(Val));
get_next_trn(Val) when is_integer(Val); Val > ?MAX_MESSAGE_TRN ->
    ?MIN_MESSAGE_TRN;
get_next_trn(Val) when is_integer(Val) ->
    Val + 1.

trn_to_str(Val) when is_integer(Val) ->
    string:right(integer_to_list(Val, 10), 2, $0).

%
% UCP message decoder
%
decode(Msg = <<?STX, BinHeader:?UCP_HEADER_LEN/binary, _/binary>>) ->
    Len = size(Msg) - 2,
    <<?STX, MsgS:Len/binary, ?ETX, Rest/binary>> = Msg,
    % TODO: handle rest of the message
    case size(Rest) of
        0 ->
            ok;
        _ ->
            {error, multiple_messages_not_supported}
    end,
    lager:info("Received UCP message: ~p", [binary:bin_to_list(MsgS)]),
    HeaderList = binary:bin_to_list(BinHeader),
    case list_to_tuple(re:split(HeaderList, "/", [{return, list}])) of
        {TRN, LEN, OR, OT} ->
            Header = #ucp_header{trn = TRN, len = LEN, o_r = OR, ot = OT},
            BodyLen = erlang:list_to_integer(LEN) - ?UCP_HEADER_LEN - ?UCP_CHECKSUM_LEN - 2,
            case Msg of
                <<?STX, _Header:?UCP_HEADER_LEN/binary, ?UCP_SEPARATOR,
                BinBody:BodyLen/binary, ?UCP_SEPARATOR,
                _CheckSum:?UCP_CHECKSUM_LEN/binary, ?ETX>> ->
                    parse_body(Header, binary:bin_to_list(BinBody));
                _ ->
                    {error, invalid_message}
            end;
        _ ->
            {error, invalid_header}
    end;

decode(_) ->
    {error, invalid_message}.

%
% Parse operations
%
parse_body(Header = #ucp_header{ot = OT, o_r = "O"}, Data) ->
    case {OT, list_to_tuple(re:split(Data, "/", [{return, list}]))} of
        {"31", {ADC, PID}} ->
            Body = #ucp_cmd_31{adc = ADC, pid = PID},
            {ok, {Header, Body}};
        {"31", _} ->
            {error, invalid_command_syntax};
        {"60", {OADC, OTON, ONPI, STYP, PWD, NPWD, VERS, LADC, LTON, LNPI, OPID, RES1}} ->
            Body = #ucp_cmd_60{ oadc = OADC,
                           oton = OTON,
                           onpi = ONPI,
                           styp = STYP,
                           pwd = ucp_utils:from_ira(binary:bin_to_list(hex:hexstr_to_bin(PWD))),
                           npwd = ucp_utils:from_ira(binary:bin_to_list(hex:hexstr_to_bin(NPWD))),
                           vers = VERS,
                           ladc = LADC,
                           lton = LTON,
                           lnpi = LNPI,
                           opid = OPID,
                           res1 = RES1 },
            {ok, {Header, Body}};
        {"60", _} ->
            {error, invalid_command_syntax};
        {"51", {ADC, OADC, AC, NRQ, NADC, NT, NPID,
             LRQ, LRAD, LPID, DD, DDT, VP, RPID, SCTS, DST, RSN, DSCTS,
             MT, NB, MSG, MMS, PR, DCS, MCLS, RPI, CPG, RPLY, OTOA, HPLMN,
             XSER, RES4, RES5}} ->
             Body = #ucp_cmd_51{adc=ADC, oadc=OADC, ac=AC, nrq=NRQ, nadc=NADC,
                          nt=NT, npid=NPID, lrq=LRQ, lrad=LRAD, lpid=LPID,
                          dd=DD, ddt=DDT, vp=VP, rpid=RPID, scts=SCTS,
                          dst=DST, rsn=RSN, dscts=DSCTS, mt=MT, nb=NB,
                          msg=MSG, mms=MMS, pr=PR, dcs=DCS, mcls=MCLS,
                          rpi=RPI, cpg=CPG, rply=RPLY, otoa=OTOA, hplmn=HPLMN,
                          xser=XSER, res4=RES4, res5=RES5},
            {ok, {Header, Body}};
        _ ->
            {error, unsupported_operation}
    end;

%
% Parse results
%
parse_body(Header = #ucp_header{ot = OT, o_r = "R"}, Data) ->
    case {OT, list_to_tuple(re:split(Data, "/", [{return, list}]))} of
        {"60", {"A", SM}} ->
            Body = #ack{ sm = SM },
            {ok, {Header, Body}};
        {"60", {"N", EC, SM}} ->
            Body = #nack{ ec = EC, sm = SM },
            {ok, {Header, Body}};
        {"60", _} ->
            {error, invalid_command_syntax};
        _ ->
            {error, unsupported_operation}
    end;

parse_body(_Header, _Body) ->
    {error, unsupported_operation}.
