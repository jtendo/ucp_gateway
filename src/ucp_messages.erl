-module(ucp_messages).
-author('rafal.galczynski@jtendo.com').
-author('andrzej.trawinski@jtendo.com').
-author('adam.rutkowski@jtendo.com').

-include("ucp_syntax.hrl").
-include("logger.hrl").

-export([
         create_cmd_31/2,
         create_cmd_51/4,
         create_cmd_51/5,
         create_cmd_60/3,
         create_ack/1]).

-define(BIN_BODY_MAX_SIZE, 140).
-define(UDH_CONCAT_IE_SIZE, 5).
-define(STK_IE, 16#70).

-ifdef(TEST).
-compile([export_all]).
-endif.

%% ---------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Create UCP 51 message
%%--------------------------------------------------------------------
create_cmd_51(TRN, Sender, Receiver, Message) ->
    create_cmd_51(TRN, Sender, Receiver, Message, []).

create_cmd_51(TRN, Sender, Receiver, Message, Options) when is_binary(Message) ->
    % TODO: Check max sender len. 16
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),
    TempBody = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA,
              rpid = "0127",
              mcls = "2", %% class message 2
              mt = "4",
              xser = "01030270000201F60D0101",
              pr = "0"},
    case check_cmd_5x_options(TempBody, Options) of
        {ok, Body} ->
            check_cmd_5x_splitting(TRN, Body, Message, Options);
        Error ->
            Error
    end;

create_cmd_51(TRN, Sender, Receiver, Message, Options) when is_list(Message) ->
    % Check max sender len. 16
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),
    {XSer, MT, ConvMessage} = case unicode:bin_is_7bit(unicode:characters_to_binary(Message)) of
        true -> {"", "3", Message};
        false -> {"020108", "4", unicode:characters_to_list(Message)}
    end,
    TempBody = #ucp_cmd_5x{
                  oadc = UCPSender,
                  adc = Receiver,
                  otoa = OTOA,
                  mt = MT,
                  xser = XSer},
    case check_cmd_5x_options(TempBody, Options) of
        {ok, Body} ->
            check_cmd_5x_splitting(TRN, Body, ConvMessage, Options);
        Error ->
            Error
    end.

check_cmd_5x_splitting(TRN, Body, Message, Options) ->
    % Check spitting option
    case proplists:get_value(split, Options, false) of
        true ->
            {result, MsgRec} = split_message(Message, Body#ucp_cmd_5x.xser, TRN),
            process_cmd_51_parts(TRN, Body, MsgRec);
        _ ->
            form_cmd_51(TRN, Body, Body#ucp_cmd_5x.xser, Message)
    end.

process_cmd_51_parts(TRN, Body, MsgRec) ->
    process_cmd_51_parts(TRN, Body, MsgRec, []).

process_cmd_51_parts(TRN, _Body, [], Result) ->
    {ok, {lists:reverse(Result), TRN}};
process_cmd_51_parts(TRN, Body, [{XSer, Message}|Rest], Result) ->
    {ok, {[MsgRec], NewTRN}} = form_cmd_51(TRN, Body, XSer, Message),
    process_cmd_51_parts(NewTRN, Body, Rest, [MsgRec | Result]).

%%--------------------------------------------------------------------
%% Form UCP 51 message
%%--------------------------------------------------------------------
form_cmd_51(TRN, Body, XSer, Message) ->
    UCPMsg = lists:flatten(hex:to_hexstr(Message)),
    NB = case Body#ucp_cmd_5x.mt of
                "4" -> integer_to_list(length(UCPMsg) * 4);
                _ -> []
         end,
    UpdatedBody = Body#ucp_cmd_5x{
                                xser = XSer,
                                nb = NB,
                                msg = UCPMsg},
    {Header, NewTRN} = create_header(TRN, "51"),
    {ok, {[{NewTRN, ucp_utils:compose_message(Header, UpdatedBody)}], NewTRN}}.

%%--------------------------------------------------------------------
%% Function checks ucp_cmd_5x options
%%--------------------------------------------------------------------
% 5x messages common options handling
check_cmd_5x_options(Rec, []) ->
    {ok, Rec};
check_cmd_5x_options(Rec, [{split, _}|T]) ->
    % pass through
    check_cmd_5x_options(Rec, T);
check_cmd_5x_options(Rec, [{notification_request, Bool}|T])
  when Bool == true ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{nrq = "1", npid = "0539", nt = "3"}, T);
check_cmd_5x_options(Rec, [{notification_type, Type}|T])
  when is_integer(Type); Type =< 0; Type =< 7 ->
    % TODO: fix NT override when notification_request option used after
    check_cmd_5x_options(Rec#ucp_cmd_5x{nt = integer_to_list(Type)}, T);
check_cmd_5x_options(Rec, [{validity_period, Value}|T]) % DDMMYYHHmm
  when is_list(Value); length(Value) =:= 10 ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{vp = Value}, T);
check_cmd_5x_options(Rec, [{deferred_delivery_time, Value}|T]) % DDMMYYHHmm
  when is_list(Value); length(Value) =:= 10 ->
    check_cmd_5x_options(Rec#ucp_cmd_5x{dd = "1", ddt = Value}, T);
check_cmd_5x_options(_Rec, [H|_T]) ->
    ?SYS_WARN("Unknown option or value: ~p", [H]),
    {error, unknown_option}.

%%--------------------------------------------------------------------
%% Function try to create UCP 60 Message Login
%%--------------------------------------------------------------------
create_cmd_60(TRN, Login,  Password) ->
    IRAPassword = lists:flatten(hex:to_hexstr(ucp_utils:to_ira(Password))),
    Body = #ucp_cmd_60{
              oadc = Login,
              oton = "6",
              onpi = "5",
              styp = "1",
              pwd = IRAPassword,
              vers = "0100"},
    {Header, NewTRN} = create_header(TRN, "60"),
    {ok, {[{NewTRN, ucp_utils:compose_message(Header, Body)}], NewTRN}}.

%%--------------------------------------------------------------------
%% Function try to create UCP 31 Alert / used as keep alive
%%--------------------------------------------------------------------
create_cmd_31(TRN, Address) ->
    Body = #ucp_cmd_31{
              adc = Address,
              pid = "0539"},
    {Header, NewTRN} = create_header(TRN, "31"),
    {ok, {[{NewTRN, ucp_utils:compose_message(Header, Body)}], NewTRN}}.


create_ack(Header) when is_record(Header, ucp_header) ->
    {ok, ucp_utils:compose_message(Header#ucp_header{o_r = "R"}, #ack{})}.

create_header(TRN, CmdId) ->
    NewTRN = ucp_utils:get_next_trn(TRN),
    Header = #ucp_header{
                  trn = ucp_utils:trn_to_str(NewTRN),
                  o_r = "O",
                  ot = CmdId},
    {Header, NewTRN}.

%%--------------------------------------------------------------------
%% Message splitting
%%--------------------------------------------------------------------
split_message(Message, XSer, Ref) when is_binary(Message) ->
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
                    add_concat_info(Result, proplists:delete(1, Services), UDH, Ref);
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

%TODO: check splitting for Text messages
split_message(Message, XSer, _Ref) ->
    {result, [{XSer, Message}]}.

add_concat_info(Bins, Services, UDH, Ref) ->
    add_concat_info(Bins, Services, UDH, Ref, length(Bins), 1, []).

add_concat_info([Bin], Services, UDH, _Ref, Parts, _PartNo, _Result) when Parts =< 1 ->
    {ok, Service1} = udh_to_service(UDH),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    {result, {XSer, Bin}};
add_concat_info([], _Services, _UDH, _Ref, _Parts, _PartNo, Result) ->
    {result, lists:reverse(Result)};
add_concat_info([H|T], Services, UDH, Ref, Parts, PartNo, Result) ->
    Ref = Ref rem 256,
    IE = {0, {info_element, {0, 3, [Ref, Parts, PartNo]}}},
    {ok, Service1} = udh_to_service([IE | UDH]),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    ModUDH = case PartNo of
                1 -> proplists:delete(?STK_IE, UDH);
                _ -> UDH
             end,
    add_concat_info(T, Services, ModUDH, Ref, Parts, PartNo+1, [{XSer, H}|Result]).

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

