-module(ucp_messages).
-author('rafal.galczynski@jtendo.com').

-include("../include/ucp_syntax.hrl").

-export([
         create_m51/4,
         create_cmd_60/3,
         create_m31/2,
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
%% @private
%% @doc
%% Function try to create UCP 51 Message
%%
%% @spec create_m51(Seq, Sender, Receiver, Message) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_m51(Seq, Sender, Receiver, Message) when is_list(Message)->
    case analyze_message(Message) of
        {'7bit', true} ->
            create_m51_normal(Seq, Sender, Receiver, Message);
        {'7bit', false} ->
            create_m51_unicode(Seq, Sender, Receiver, Message)
    end;

create_m51(Seq, Sender, Receiver, Message) when is_binary(Message)->
    Tpdus = smspp:create_tpud_message(Message),
    lists:map(fun(X) ->
                      create_m51_binary(ucp_utils:get_next_seq(Seq), Sender, Receiver, X) end,
              Tpdus).

%% ---------------------------------------------------------------------
%% Internals
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to create UCP 51 Message having utf-8 chars
%%
%% @spec create_m51_unicode(Seq, Sender, Receiver, Message) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_m51_unicode(Seq, Sender, Receiver, Message) ->
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    HexStr = hex:list_to_hexstr(
               unicode:characters_to_list(Message)),

    HexMessage = lists:flatten(
                   [ ucp_utils:fill_with_zeros(X,4) || X <- HexStr ]),

    XSER = "020108",
    NB = integer_to_list(length(HexMessage)*4),
    Body = #ucp_cmd_51{
      oadc=UCPSender,
      adc=Receiver,
      otoa=OTOA,
      mt = "4",
      nb = NB,
      xser = XSER,
      msg=HexMessage},

    MessageLen =
        length(UCPSender++Receiver++HexMessage++XSER++NB) +
        ?HEADER_LEN + ?EMPTY_BODY_LEN_51,

    Header = #ucp_header{
      trn=Seq,
      len=ucp_utils:fill_with_zeros(MessageLen,5),
      o_r="O",
      ot="51"},

    UcpMessage = ucp_utils:compose_message(Header, Body),
    {ok, UcpMessage}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to create UCP 51 Message not having utf-8 chars
%%
%% @spec create_m51_normal(Seq, Sender, Receiver, Message) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_m51_normal(Seq, Sender, Receiver, Message) ->

    UCPMsg = hex:list_to_hexstr(
               ucp_utils:to_ira(Message)),
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    Body = #ucp_cmd_51{
      oadc=UCPSender,
      adc=Receiver,
      otoa=OTOA,
      mt = "3",
      msg=UCPMsg},

    MessageLen = length(UCPSender++Receiver) +
        length(UCPMsg)*2 +
        ?HEADER_LEN +
        ?EMPTY_BODY_LEN_51,


    Header = #ucp_header{
      trn=Seq,
      len=ucp_utils:fill_with_zeros(MessageLen,5),
      o_r="O",
      ot="51"},

    UcpMessage = ucp_utils:compose_message(Header, Body),
    {ok, UcpMessage}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to create UCP 51 Message not having utf-8 chars
%%
%% @spec create_m51_binary(Seq, Sender, Receiver, Message) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_m51_binary(Seq, Sender, Receiver, Message) ->

    UCPMsg = hex:bin_to_hexstr(Message),
    {otoa, OTOA, sender, UCPSender} = ucp_utils:calculate_sender(Sender),

    Body = #ucp_cmd_51{
      oadc=UCPSender,
      adc=Receiver,
      otoa=OTOA,
      rpid = "0127",
      mcls = "2", %% class message 2
      xser = "01030270000201F6",
      mt = "4",
      msg=UCPMsg},

    MessageLen = length(UCPSender++Receiver) +
        length(UCPMsg)*2 +
        ?HEADER_LEN +
        ?EMPTY_BODY_LEN_51,

    Header = #ucp_header{
      trn=Seq,
      len=ucp_utils:fill_with_zeros(MessageLen,5),
      o_r="O",
      ot="51"},

    UcpMessage = ucp_utils:compose_message(Header, Body),
    {ok, UcpMessage}.




%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to create UCP 60 Message Login
%%
%% @spec create_m60(Seq, Login, Password) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_cmd_60(Trn, Login,  Password) ->
    IRAPassword = hex:list_to_hexstr(ucp_utils:to_ira(Password)),
    STYP = "1",
    OTON = "6",
    ONPI = "5",
    Body = #ucp_cmd_60{
      oadc=Login,
      oton=OTON,
      onpi=ONPI,
      styp=STYP,
      pwd = IRAPassword,
      vers = "0100"},

    MessageLen = length(IRAPassword)*2 +
        length(Login++STYP++OTON++ONPI) +
        ?HEADER_LEN + ?EMPTY_BODY_LEN_60,

    Header = #ucp_header{
      trn=seq_to_string(Seq),
      len=ucp_utils:fill_with_zeros(MessageLen,5),
      o_r="O",
      ot="60"},

    UcpMessage = ucp_utils:compose_message(Header, Body),
    {ok, UcpMessage}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to create UCP 31 Alert / used as keep alive
%%
%% @spec create_m31(Seq, Address) -> {ok, UcpMsg}
%% @end
%%--------------------------------------------------------------------

create_m31(Seq, Address) ->
    Body = #ucp_cmd_31{
      adc=Address,
      pid = "0539"},

    MessageLen = length(Address) + ?HEADER_LEN + ?EMPTY_BODY_LEN_31,

    Header = #ucp_header{
      trn=Seq,
      len=ucp_utils:fill_with_zeros(MessageLen,5),
      o_r="O",
      ot="31"},

    UcpMessage = ucp_utils:compose_message(Header, Body),
    {ok, UcpMessage}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function splits list into list of lists each Num long
%%
%% @spec partition_by([], Int) -> []
%% @end
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
%% @private
%% @doc
%% Function checks if String contains utf8 chars
%%
%% @spec analyze_message(String) -> {'7bit', true} | {'7bit', false}
%% @end
%%--------------------------------------------------------------------

analyze_message(Message) ->
    Bit = unicode:bin_is_7bit(unicode:characters_to_binary(Message)),
    {'7bit', Bit}.

seq_to_string(S) -> string:right(integer_to_list(S, 10), 2, $0).
