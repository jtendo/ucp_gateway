-module(ucp_messages).
-author('rafal.galczynski@jtendo.com').
-author('andrzej.trawinski@jtendo.com').
-author('adam.rutkowski@jtendo.com').

-include("ucp_syntax.hrl").
-include("logger.hrl").

-export([
         create_cmd_51_text/4,
         create_cmd_51_text/5,
         create_cmd_51_binary/4,
         create_cmd_51_binary/5,
         create_cmd_60/3,
         create_cmd_31/2,
         create_ack/1,
         split_message/3,
         analyze_message/1]).

%-ifdef(TEST).
-compile([export_all]).
%-endif.

-define(BIN_BODY_MAX_SIZE, 140).
-define(UDH_CONCAT_IE_SIZE, 5).
-define(STK_IE, 16#70).


%% ---------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------

split_message(Message, XSer, CNTR) when is_binary(Message) ->
    % TODO: catch parsing errors
    {ok, Services} = xser_to_services(XSer),
    {ok, L} = service_to_udh(proplists:get_value(1, Services)),
    % Remove IE: 00 (Concatenated short messages IE) if exists
    UDH = proplists:delete(0, L),
    % Check - do we need splitting
    UDHL = get_udh_size(UDH),
    case ((size(Message) + UDHL) > ?BIN_BODY_MAX_SIZE) of
        true ->
            case do_splitting(Message, UDH) of
                {ok, Result} ->
                    % pass services without UDH - we'll build it inside
                    add_concat_info(Result, proplists:delete(1, Services), UDH, CNTR);
                Error ->
                    Error
            end;
        _ ->
            % splitting not needed
            ModXSer = case UDHL of
                         0 -> XSer;
                         _ ->
                            {ok, Service1} = udh_to_service(UDH),
                            {ok, NewXSer} = services_to_xser([Service1 | proplists:delete(1, Services)]),
                            NewXSer
                      end,
            {result, [{ModXSer, Message}]}
    end;

split_message(Message, XSer, CNTR) when is_list(Message) ->
    BinMessage = list_to_binary(Message),
    split_message(BinMessage, XSer, CNTR).


add_concat_info(Bins, Services, UDH, CNTR) ->
    add_concat_info(Bins, Services, UDH, CNTR, length(Bins), 1, []).

add_concat_info([Bin], Services, UDH, _CNTR, Parts, _PartNo, _Result) when Parts =< 1 ->
    {ok, Service1} = udh_to_service(UDH),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    {result, {XSer, Bin}};
add_concat_info([], _Services, _UDH, _CNTR, _Parts, _PartNo, Result) ->
    {result, lists:reverse(Result)};
add_concat_info([H|T], Services, UDH, CNTR, Parts, PartNo, Result) ->
    Ref = CNTR rem 256,
    IE = {0, {info_element, {0, 3, [Ref, Parts, PartNo]}}},
    {ok, Service1} = udh_to_service([IE | UDH]),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    ModUDH = case PartNo of
                1 -> proplists:delete(?STK_IE, UDH);
                _ -> UDH
             end,
    add_concat_info(T, Services, ModUDH, CNTR, Parts, PartNo+1, [{XSer, H}|Result]).

%%--------------------------------------------------------------------
%% Perform message splitting
%%--------------------------------------------------------------------
do_splitting(Message, UDH) ->
    do_splitting(Message, UDH, []).

do_splitting(_, _, Result) when length(Result) > 4 ->
    {error, message_too_long};
do_splitting([], _, Result) ->
    {ok, lists:reverse(Result)};
do_splitting(Message, UDH, []) ->
    % Handle first part
    UDHL = get_udh_size(UDH, ?UDH_CONCAT_IE_SIZE),
    case ((size(Message) + UDHL) > ?BIN_BODY_MAX_SIZE) of
        true ->
            MaxSize = ?BIN_BODY_MAX_SIZE - UDHL,
            <<Part:MaxSize/binary, Rest/binary>> = Message,
            % HACK: remove STK header if exists (70)
            ModUDH = proplists:delete(?STK_IE, UDH),
            do_splitting(Rest, ModUDH, [Part]);
        _ ->
            do_splitting([], UDH, [Message])
    end;
do_splitting(Message, UDH, Result) ->
    % Handle following parts
    UDHL = get_udh_size(UDH, ?UDH_CONCAT_IE_SIZE),
    case ((size(Message) + UDHL) > ?BIN_BODY_MAX_SIZE) of
        true ->
            MaxSize = ?BIN_BODY_MAX_SIZE - UDHL,
            <<Part:MaxSize/binary, Rest/binary>> = Message,
            do_splitting(Rest, UDH, [Part | Result]);
        _ ->
            do_splitting([], UDH, [Message | Result])
    end.

%%--------------------------------------------------------------------
%% Translating XSer string into services and vice versa
%%--------------------------------------------------------------------
xser_to_services(XSer) ->
    % transform hexstr to list
    xser_to_services(hex:hexstr_to_list(XSer), []).

xser_to_services([], Acc) ->
    {ok, Acc};
xser_to_services([Type, Len | Tail], Acc) ->
    Data = lists:sublist(Tail, Len),
    Rest = lists:nthtail(Len, Tail),
    xser_to_services(Rest, [{Type, {service, {Type, Len, Data}}} | Acc]).

services_to_xser(L) ->
    Sorted = lists:reverse(lists:keysort(1, L)),
    services_to_xser(Sorted, []).

services_to_xser([], Result) ->
    {ok, lists:flatten(hex:to_hexstr(Result))};
services_to_xser([{Type, {service, {Type, Len, Data}}} | Rest], Result) ->
    services_to_xser(Rest, [Type, Len, Data | Result]).

%%--------------------------------------------------------------------
%% Translating services to udh elements and vice versa
%%--------------------------------------------------------------------
service_to_udh({service, {1, _, [_Len | Data]}}) -> % cut off UDHL
    service_to_udh(Data, []);
service_to_udh(_) ->
    {ok, []}.

service_to_udh([], Acc) ->
    {ok, Acc};
service_to_udh([IEI, IEILen | Tail], Acc) ->
    IEIData = lists:sublist(Tail, IEILen),
    Rest = lists:nthtail(IEILen, Tail),
    service_to_udh(Rest, [{IEI, {info_element, {IEI, IEILen, IEIData}}} | Acc]).

udh_to_service([]) ->
    {ok, []};
udh_to_service(L) ->
    Sorted = lists:reverse(lists:keysort(1, L)),
    udh_to_service(Sorted, []).

udh_to_service([], Result) ->
    Data = lists:flatten(Result),
    Len = length(Data),
    {ok, {1, {service, {1, Len+1, [Len | Data]}}}};
udh_to_service([{IEI, {info_element, {IEI, IEILen, IEIData}}} | Rest], Result) ->
    udh_to_service(Rest, [IEI, IEILen, IEIData | Result]).

%%--------------------------------------------------------------------
%% Calculate UDH size
%%--------------------------------------------------------------------
get_udh_size(L) ->
    get_udh_size(L, 0).

get_udh_size([], Size) ->
    case Size of
        0 -> 0;
        _ -> Size + 1 % +1 for UDHL field
    end;
get_udh_size([{_IEI, {info_element, {_IEI, IEILen, _IEIData}}} | Rest], Size) ->
    get_udh_size(Rest, Size + 2 + IEILen).

%%--------------------------------------------------------------------
%% Create UCP 51 message
%%--------------------------------------------------------------------
create_cmd_51_text(Trn, Sender, Receiver, Message) when is_list(Message)->
    create_cmd_51_text(Trn, Sender, Receiver, Message, []).

create_cmd_51_text(Trn, Sender, Receiver, Message, Options) when is_list(Message)->
    case analyze_message(Message) of
        {'7bit', true} ->
            create_cmd_51_normal(Trn, Sender, Receiver, Message, Options);
        {'7bit', false} ->
            create_cmd_51_unicode(Trn, Sender, Receiver, Message, Options)
    end.

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message not having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_binary(Trn, Sender, Receiver, Message) when is_binary(Message) ->
    create_cmd_51_binary(Trn, Sender, Receiver, Message, []).

create_cmd_51_binary(Trn, Sender, Receiver, Message, Options) when is_binary(Message) ->

    {ok, L} = binpp:convert(Message),
    lager:debug("Binary msg content: ~p", [L]),
    UCPMsg = lists:flatten(hex:to_hexstr(Message)),
    % Check max sender len. 16
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),

    TempBody = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              nrq = "1",
              nt = "3",
              npid = "0539",
              rpid = "0127",
              mcls = "2", %% class message 2
              mt = "4",
              nb = integer_to_list(length(UCPMsg)*4),
              msg = UCPMsg,
              pr = "0"},
    Header = #ucp_header{
              trn = ucp_utils:trn_to_str(Trn),
              o_r = "O",
              ot = "51"},
    {ok, Body} = check_cmd_5x_bin_options(TempBody, Options),
    {ok, ucp_utils:compose_message(Header, Body)}.

%% ---------------------------------------------------------------------
%% Internals
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_unicode(Trn, Sender, Receiver, Message, Options) ->
    % Check max sender len. 16
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),

    HexStr = hex:to_hexstr(unicode:characters_to_list(Message)),

    HexMessage = lists:flatten(
                   [string:right(X, 4, $0) || X <- HexStr]),

    XSER = "020108",
    NB = integer_to_list(length(HexMessage)*4),
    TempBody = #ucp_cmd_5x{
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
    case check_cmd_5x_options(TempBody, Options) of
        {ok, Body} ->
            {ok, ucp_utils:compose_message(Header, Body)};
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
%% Function try to create UCP 51 Message not having utf-8 chars
%%--------------------------------------------------------------------
create_cmd_51_normal(Trn, Sender, Receiver, Message, Options) ->

    UCPMsg = lists:flatten(hex:to_hexstr(ucp_utils:to_ira(Message))),
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),

    TempBody = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              mt = "3",
              msg = UCPMsg},
    Header = #ucp_header{
              trn = ucp_utils:trn_to_str(Trn),
              o_r = "O",
              ot = "51"},
    case check_cmd_5x_options(TempBody, Options) of
        {ok, Body} ->
            {ok, ucp_utils:compose_message(Header, Body)};
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
%% Function checks ucp_cmd_5x options
%%--------------------------------------------------------------------

% 5x binary message specific options handling
check_cmd_5x_bin_options(Rec, Opts) ->
    check_cmd_5x_bin_options(Rec, Opts, Opts).

check_cmd_5x_bin_options(Rec, [], Opts) ->
   check_cmd_5x_options(Rec, Opts);
check_cmd_5x_bin_options(Rec, [{extra_services, Value}|T], Opts)
   when is_list(Value) ->
      check_cmd_5x_bin_options(Rec#ucp_cmd_5x{xser = Value}, T, Opts);
check_cmd_5x_bin_options(Rec, [_H|T], Opts) ->
   % Option unknown or incorrect value: ~w", [H]).
   check_cmd_5x_bin_options(Rec, T, Opts).

% 5x messages common options handling
check_cmd_5x_options(Rec, []) ->
    {ok, Rec};
check_cmd_5x_options(Rec, [{notification_request, Bool}|T])
  when Bool == true ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{nrq = "1"}, T);
check_cmd_5x_options(Rec, [{notification_type, Type}|T])
  when is_integer(Type); Type =< 0; Type =< 7 ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{nt = integer_to_list(Type)}, T);
check_cmd_5x_options(Rec, [{extra_services, Value}|T])
  when is_binary(Value) ->
    {ok, HexXser} = binpp:convert(Value),
    check_cmd_5x_options(Rec#ucp_cmd_5x{xser = lists:flatten(HexXser)}, T);
check_cmd_5x_options(Rec, [{validity_period, Value}|T]) % DDMMYYHHmm
  when is_list(Value); length(Value) =:= 10 ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{vp = Value}, T);
check_cmd_5x_options(Rec, [{deferred_delivery_time, Value}|T]) % DDMMYYHHmm
  when is_list(Value); length(Value) =:= 10 ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{dd = "1", ddt = Value}, T);
check_cmd_5x_options(Rec, [_H|T]) ->
    % TODO: return error
    % Option unknown or incorrect value: ~w", [H]).
    check_cmd_5x_options(Rec, T).

%%--------------------------------------------------------------------
%% Function try to create UCP 60 Message Login
%%--------------------------------------------------------------------
create_cmd_60(Trn, Login,  Password) ->
    IRAPassword = lists:flatten(hex:to_hexstr(ucp_utils:to_ira(Password))),
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
%% Function checks if String contains utf8 chars
%%--------------------------------------------------------------------
analyze_message(Message) ->
    Bit = unicode:bin_is_7bit(unicode:characters_to_binary(Message)),
    {'7bit', Bit}.

