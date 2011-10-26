-module(ucp_utils).
-author('rafal.galczynski@jtendo.com').
-include("../include/ucp_syntax.hrl").
-include("../include/logger.hrl").

-compile([debug_info]).

-export([
         to_ira/1,
         to_7bit/1,
         calculate_sender/1,
         fill_with_zeros/2,
         compose_message/2,
         unpackUCP/1,
         analyze_ucp_body/1,
         binary_split/2,
         pad_to/2,
         get_next_seq/1
         %% create_ieia_00/3,
         %% create_ieia_05/2,
         %% create_udh/1,
         %% create_dcs_normal/0,
         %% create_dcs_binary/0
        ]).

-define(STX,16#02).
-define(ETX,16#03).


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
    GsmMessage = lists:map(
                   fun(X) -> ucp_ia5:ascii_to_gsm(X) end, Str),
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

to_7bit(Str) ->
    binary:bin_to_list(ucp_7bit:to_7bit(Str)).

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
            { otoa, "1139", sender, Sender};
        false ->
            { otoa, "5039", sender, append_length(
                                      hex:list_to_hexstr(
                                        to_7bit(
                                          to_ira(Sender))))}
    end.

%% create_ieia_00(RefNo, Total, Actual) ->
%%     "0003" ++ hex:int_to_hexstr(RefNo) ++ hex:int_to_hexstr(Total)
%%         ++ hex:int_to_hexstr(Actual).

%% create_ieia_05(SourcePort, DestPort) ->
%%     "0504" ++ hex:int_to_hexstr(SourcePort) ++ hex:int_to_hexstr(DestPort).

%% create_udh(DDList) ->
%%     TT = "01",
%%     DD = lists:append(DDList),
%%     UDHL = trunc(length(DD)/2),
%%     LL = UDHL+1,
%%     UDH = lists:append([
%%                   TT,
%%                   hex:int_to_hexstr(LL),
%%                   hex:int_to_hexstr(UDHL),
%%                         DD]),
%%     UDH.

%% create_dcs_binary() ->
%%     "0201F5".

%% create_dcs_normal() ->
%%     "020100".


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for composing whole ucp message
%%
%% @spec compose_message(Header, Body) -> Bin
%% @end
%%--------------------------------------------------------------------
compose_message(Header, Body) ->
    BodyFields = lists:nthtail(1,tuple_to_list(Body)),
    HeaderFields = lists:nthtail(1,tuple_to_list(Header)),
    UcpMessage = lists:flatten(
                   string:join(HeaderFields,"/") ++"/"++
                       string:join(BodyFields,"/")),
    CRC = calculate_crc(UcpMessage),
    CompleteUcpMessage =  UcpMessage++CRC,
    ?SYS_DEBUG("Sending UCPMsg: ~p",[CompleteUcpMessage]),
    binary:list_to_bin([?STX,CompleteUcpMessage,?ETX]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for composing whole ucp message
%%
%% @spec unpackUCP(Bin) -> {Header, Body} |
%%                                    {error, wrong_message}
%% @end
%%--------------------------------------------------------------------
unpackUCP(<<>>) ->
    {error, empty_message};

unpackUCP(Binary) ->
    Ucp = binary:bin_to_list(Binary),
    ?SYS_DEBUG("Received UCP Frame > ~s",[string:sub_string(Ucp,2)]),
    case list_to_tuple(re:split(Ucp,"/")) of
        %% message 31 ACK
        {TRN, LEN, OR, OT, <<"A">>, SM, CRC} ->
            Header = #header{trn=TRN, len=LEN, o_r=OR, ot=OT},
            Body = #ack{ack="A", sm=SM, crc=CRC},
            {Header, Body};
        %% message 51 ACK
        {TRN, LEN, OR, OT, <<"A">>, MVP, SM, CRC} ->
            Header = #header{trn=TRN, len=LEN, o_r=OR, ot=OT},
            Body = #ack{ack="A", mvp=MVP, sm=SM, crc=CRC},
            {Header, Body};
        %% common NACK
        {TRN, LEN, OR, OT, <<"N">>, EC, SM, CRC} ->
            Header = #header{trn=TRN, len=LEN, o_r=OR, ot=OT},
            Body = #nack{nack="N", ec=EC, sm=SM,crc=CRC},
            {Header, Body};
        %% message 5X
        {TRN, LEN, OR, OT, ADC, OADC, AC, NRQ, NADC, NT, NPID,
         LRQ, LRAD, LPID, DD, DDT, VP, RPID, SCTS, DST, RSN,
         DSCTS, MT, NB, MSG, MMS, PR, DCS, MCLS, RPI, CPG,
         RPLY, OTOA, HPLMN, XSER, RES4, RES5, CRC} ->
            Header = #header{trn=TRN, len=LEN, o_r=OR, ot=OT},
            Body = #ucp5x{adc=ADC, oadc=OADC, ac=AC, nrq=NRQ, nadc=NADC,
                          nt=NT, npid=NPID, lrq=LRQ, lrad=LRAD, lpid=LPID,
                          dd=DD, ddt=DDT, vp=VP, rpid=RPID, scts=SCTS,dst=DST,
                          rsn=RSN, dscts=DSCTS, mt=MT, nb=NB, msg=MSG,
                          mms=MMS, pr=PR, dcs=DCS, mcls=MCLS, rpi=RPI,
                          cpg=CPG, rply=RPLY, otoa=OTOA, hplmn=HPLMN,
                          xser=XSER, res4=RES4, res5=RES5, crc=CRC},
            {Header, Body};
        Other ->
            ?SYS_DEBUG("~p ~p", ["Received UNKNOWN MESSAGE",Other]),
            {error, wrong_message}
    end.



%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for analyze upc body record
%%
%% @spec analyze_ucp_body(Body) -> {ack,ok} |
%%                                  {nack, system_message} |
%%                                  {error, unknow_response}
%% @end
%%--------------------------------------------------------------------

analyze_ucp_body(BodyRec) when is_record(BodyRec, ack) ->
    {ack,ok};

analyze_ucp_body(BodyRec) when is_record(BodyRec, nack) ->
    {nack, BodyRec#nack.sm};

analyze_ucp_body(BodyRec) when is_record(BodyRec, ucp5x) ->
    {ucp5x, BodyRec#ucp5x.msg};

analyze_ucp_body(_) ->
    {error, unknow_response}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for appending list length to biggining of the list
%%
%% @spec append_length(List) -> []
%% @end
%%--------------------------------------------------------------------

append_length(L) ->
    Fun = fun([H|_]) -> H == $0 end,
    {ElemsWithZero, ElemsWithOutZero} = lists:partition(Fun, L),
    Len = length(ElemsWithOutZero)*2
        + length(ElemsWithZero),
    HexStr = hex:int_to_hexstr(Len),
    lists:flatten([HexStr, L]).


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for appending specified numer of "0" chars
%%
%% @spec fill_with_zeros(Value, NumerOfZeros) -> String
%% @end
%%--------------------------------------------------------------------

fill_with_zeros(Value, Zeros) when is_list(Value)->
    case string:len(Value) >= Zeros of
        true ->
            Value;
        false ->
            Diff = Zeros - string:len(Value),
            string:concat(string:chars($0, Diff),Value)
    end;

fill_with_zeros(Value, Zeros) when is_integer(Value)->
    StrZeros = integer_to_list(Zeros),
    StrFormat = "~"++StrZeros++"."++StrZeros++".0w",
    lists:flatten(
      io_lib:format(StrFormat,[Value])).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for getting 8 last significant bits of number
%%
%% @spec get_8lsb(Integer) -> Integer
%% @end
%%--------------------------------------------------------------------

get_8lsb(Integer) ->
    Integer band 255.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for calculating CRC checksum for UCP Message
%%
%% @spec calculate_crc(Message) -> HexString
%% @end
%%--------------------------------------------------------------------

calculate_crc(UcpMessage) ->
    hex:int_to_hexstr(
      get_8lsb(
        lists:sum(UcpMessage))).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for checking if Char is digit
%%
%% @spec is_digit(Char) -> true | false
%% @end
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



%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns next sequence number for given seq as string
%%
%% @spec get_next_seq(SeqNo) -> Str
%% @end
%%--------------------------------------------------------------------
get_next_seq(SeqNo) when is_integer(SeqNo)->
    case SeqNo =:= 99 of
        true ->
            "00";
        false ->
            fill_with_zeros(SeqNo+1,2)
    end;

get_next_seq(SeqNo) when is_list(SeqNo)->
    Int = list_to_integer(SeqNo),
    get_next_seq(Int).
