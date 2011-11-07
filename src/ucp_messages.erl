-module(ucp_messages).
-author('rafal.galczynski@jtendo.com').
-author('andrzej.trawinski@jtendo.com').

-include("ucp_syntax.hrl").

-export([
         create_cmd_51_text/4,
         create_cmd_51_binary/4,
         create_cmd_60/3,
         create_cmd_31/2,
         create_ack/1,
         partition_by/2,
         analyze_message/1]).

-compile([debug_info]).

-define(BODY_LEN, 153).
-define(HEADER_LEN, 14).
-define(EMPTY_BODY_LEN_51, 40).
-define(EMPTY_BODY_LEN_60, 18).
-define(EMPTY_BODY_LEN_31, 8).
-define(BIN_BODY_MAX_SIZE, 140).


%% ---------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Create UCP 51 message
%%--------------------------------------------------------------------
create_cmd_51_text(Trn, Sender, Receiver, Message) when is_list(Message)->
    case analyze_message(Message) of
        {'7bit', true} ->
            create_cmd_51_normal(Trn, Sender, Receiver, Message);
        {'7bit', false} ->
            create_cmd_51_unicode(Trn, Sender, Receiver, Message)
    end.

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message not having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_binary(Trn, Sender, Receiver, Message) when is_binary(Message) ->

    {ok, L} = binpp:convert(Message),
    lager:debug("Binary msg content: ~p", [L]),

    UCPMsg = lists:flatten(hex:to_hexstr(Message)),
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    Body = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              rpid = "0127",
              mcls = "2", %% class message 2
              xser = "0103027000",
              mt = "4",
              nb = integer_to_list(length(UCPMsg)*4),
              msg = UCPMsg},
    Header = #ucp_header{
              trn = ucp_utils:trn_to_str(Trn),
              o_r = "O",
              ot = "51"},
    {ok, ucp_utils:compose_message(Header, Body)}.

%% ---------------------------------------------------------------------
%% Internals
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_unicode(Trn, Sender, Receiver, Message) ->
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    HexStr = hex:list_to_hexstr(unicode:characters_to_list(Message)),

    HexMessage = lists:flatten(
                   [string:right(X, 4, $0) || X <- HexStr]),

    XSER = "020108",
    NB = integer_to_list(length(HexMessage)*4),
    Body = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              mt = "4",
              nb = NB,
              xser = XSER,
              msg = HexMessage},
    Header = #ucp_header{
              trn = ucp_utils:trn_to_str(Trn),
              o_r = "O",
              ot = "51"},
    {ok, ucp_utils:compose_message(Header, Body)}.

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message not having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_normal(Trn, Sender, Receiver, Message) ->

    UCPMsg = lists:flatten(hex:list_to_hexstr(ucp_utils:to_ira(Message))),
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    Body = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              mt = "3",
              msg = UCPMsg},
    Header = #ucp_header{
              trn = ucp_utils:trn_to_str(Trn),
              o_r = "O",
              ot = "51"},
    {ok, ucp_utils:compose_message(Header, Body)}.

%%--------------------------------------------------------------------
%% Function try to create UCP 60 Message Login
%%--------------------------------------------------------------------
create_cmd_60(Trn, Login,  Password) ->
    IRAPassword = lists:flatten(hex:list_to_hexstr(ucp_utils:to_ira(Password))),
    Body = #ucp_cmd_60{
              oadc = Login,
              oton = "6",
              onpi = "5",
              styp = "1",
              pwd = IRAPassword,
              vers = "0100"},
    Header = #ucp_header{
                  trn = ucp_utils:trn_to_str(Trn),
                  o_r = "O",
                  ot = "60"},
    {ok, ucp_utils:compose_message(Header, Body)}.


%%--------------------------------------------------------------------
%% Function try to create UCP 31 Alert / used as keep alive
%%--------------------------------------------------------------------
create_cmd_31(Trn, Address) ->
    Body = #ucp_cmd_31{
              adc = Address,
              pid = "0539"},
    Header = #ucp_header{
                  trn = ucp_utils:trn_to_str(Trn),
                  o_r = "O",
                  ot = "31"},
    {ok, ucp_utils:compose_message(Header, Body)}.


create_ack(Header) when is_record(Header, ucp_header) ->
    {ok, ucp_utils:compose_message(Header#ucp_header{o_r = "R"}, #ack{})}.


%%--------------------------------------------------------------------
%% Function splits list into list of lists each Num long
%%--------------------------------------------------------------------
partition_by(L, Num)->
    partition_by(L,Num,[]).

partition_by(L, Num, Acc) when length(L) =< Num ->
    lists:reverse([L|Acc]);

partition_by(L, Num, Acc) when length(L) > Num ->
    {H, T} = lists:split(Num, L),
    partition_by(T,Num,[H|Acc]);

partition_by([], _Num, Acc)->
    lists:reverse(Acc).


%%--------------------------------------------------------------------
%% Function checks if String contains utf8 chars
%%--------------------------------------------------------------------
analyze_message(Message) ->
    Bit = unicode:bin_is_7bit(unicode:characters_to_binary(Message)),
    {'7bit', Bit}.

