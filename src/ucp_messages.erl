-module(ucp_messages).
-author('andrzej.trawinski@jtendo.com').

-include_lib("ucp_common/include/ucp_syntax.hrl").
-include("logger.hrl").

-export([create_cmd_31_body/1,
         create_cmd_51_body/4,
         create_cmd_51_body/5,
         create_cmd_60_body/2,
         create_ack/1]).

-export([services_to_xser/1]).

-define(BIN_BODY_MAX_SIZE, 140).
-define(UDH_CONCAT_IE_SIZE, 5).
-define(STK_IE, 16#70).

%% ---------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Create UCP 51 message
%%--------------------------------------------------------------------
create_cmd_51_body(CRef, Sender, Receiver, Message) ->
    create_cmd_51_body(CRef, Sender, Receiver, Message, []).

create_cmd_51_body(CRef, Sender, Receiver, Message, Options) ->
    % TODO: Check max sender len. 16
    {OTOA, UCPSender} = ucp_utils:encode_sender(Sender),
    TempBody = #ucp_cmd_5x{
              oadc = UCPSender,
              adc = Receiver,
              otoa = OTOA},
    UpdOptions = check_msg_type(Message, Options),
    UpdMessage = convert_msg(Message),
    case process_cmd_5x_options(TempBody, UpdOptions) of
        {ok, Body} ->
            check_cmd_5x_splitting(CRef, Body, UpdMessage, UpdOptions);
        Error ->
            Error
    end.

check_msg_type(Message, Options) ->
    case proplists:is_defined(message_type, Options) of
        true -> Options;
        false -> [{message_type, detect_msg_type(Message)} | Options]
    end.

detect_msg_type(Message) when is_binary(Message) ->
    binary;
detect_msg_type(Message) when is_list(Message) ->
    text.

convert_msg(Message) when is_binary(Message) ->
    Message;
convert_msg(Message) when is_list(Message) ->
    % TODO: convert unicode lists
    % if unicode:bin_is_7bit(unicode:characters_to_binary(Message))
    % unicode:characters_to_list(Message)
    erlang:list_to_binary(Message).

check_cmd_5x_splitting(CRef, Body, Message, Options) ->
    % Check spitting option
    case proplists:get_value(split, Options, false) of
        true ->
            {result, MsgRec, NewCRef} = split_message(CRef, Body#ucp_cmd_5x.xser, Message),
            process_cmd_51_parts(NewCRef, Body, MsgRec);
        _ ->
            {ok, CRef, [form_cmd_51_body(Body, Body#ucp_cmd_5x.xser, Message)]}
    end.

process_cmd_51_parts(CRef, Body, MsgRec) ->
    process_cmd_51_parts(CRef, Body, MsgRec, []).

process_cmd_51_parts(CRef, _Body, [], Result) ->
    {ok, CRef, lists:reverse(Result)};
process_cmd_51_parts(CRef, Body, [{XSer, Message}|Rest], Result) ->
    UpdatedBody = form_cmd_51_body(Body, XSer, Message),
    process_cmd_51_parts(CRef, Body, Rest, [UpdatedBody | Result]).

%%--------------------------------------------------------------------
%% Form UCP 51 message
%--------------------------------------------------------------------
form_cmd_51_body(Body, XSer, Message) ->
    UCPMsg = lists:flatten(ucp_utils:to_hexstr(Message)),
    NB = case Body#ucp_cmd_5x.mt of
                "4" -> integer_to_list(length(UCPMsg) * 4);
                _ -> []
         end,
    UpdatedBody = Body#ucp_cmd_5x{
                        xser = XSer,
                        nb = NB,
                        msg = UCPMsg},
    {cmd_body, "51", UpdatedBody}.

%%--------------------------------------------------------------------
%% Function checks ucp_cmd_5x options
%%--------------------------------------------------------------------
% 5x messages common options handling
process_cmd_5x_options(Rec, Opts) ->
    process_cmd_5x_options(Rec, Opts, Opts).

process_cmd_5x_options(Rec, _Opts, []) ->
    {ok, Rec};
process_cmd_5x_options(Rec, Opts, [{split, _}|T]) ->
    % pass through
    process_cmd_5x_options(Rec, Opts, T);
process_cmd_5x_options(Rec, Opts, [{notification_request, Value}|T])
  when is_boolean(Value) ->
    case Value of
        true ->
            NewRec = case proplists:get_value(notification_type, Opts) of
                        undefined ->
                            % Set default notification type when not specified
                            Rec#ucp_cmd_5x{nt = "3"};
                        _ ->
                            Rec
                     end,
            process_cmd_5x_options(NewRec#ucp_cmd_5x{nrq = "1", npid = "0539"}, Opts, T);
        false ->
            process_cmd_5x_options(Rec, Opts, T)
    end;
process_cmd_5x_options(_Rec, _Opts, [{notification_request, Value}|_T]) ->
    {error, {invalid_option_value, {notification_request, Value}}};
process_cmd_5x_options(Rec, Opts, [{notification_type, Type}|T])
  when is_integer(Type), Type >= 0, Type =< 7 ->
    process_cmd_5x_options(Rec#ucp_cmd_5x{nt = integer_to_list(Type)}, Opts, T);
process_cmd_5x_options(_Rec, _Opts, [{notification_type, Type}|_T]) ->
    {error, {invalid_option_value, {notification_type, Type}}};
process_cmd_5x_options(Rec, Opts, [{validity_period, Value}|T]) % DDMMYYHHmm
  when is_list(Value), length(Value) =:= 10 ->
    process_cmd_5x_options(Rec#ucp_cmd_5x{vp = Value}, Opts, T);
process_cmd_5x_options(_Rec, _Opts, [{validity_period, Value}|_T]) ->
    {error, {invalid_option_value, {validity_period, Value}}};
process_cmd_5x_options(Rec, Opts, [{deferred_delivery_time, Value}|T]) % DDMMYYHHmm
  when is_list(Value), length(Value) =:= 10 ->
    process_cmd_5x_options(Rec#ucp_cmd_5x{dd = "1", ddt = Value}, Opts, T);
process_cmd_5x_options(_Rec, _Opts, [{deferred_delivery_time, Value}|_T]) ->
    {error, {invalid_option_value, {deferred_delivery_time, Value}}};
% message_type handling
process_cmd_5x_options(Rec, Opts, [{message_type, Type}|T])
  when is_atom(Type) ->
    % do not process message types when user
    % specified custom XSer value
    case proplists:get_value(xser, Opts) of
        undefined ->
            case lists:member(Type, get_message_types()) of
                false ->
                    {error, {invalid_option_value, {message_type, Type}}};
                true ->
                    NewRec = apply_message_type(Type, Rec),
                    process_cmd_5x_options(NewRec, Opts, T)
            end;
        _ ->
            % continue options processing
            process_cmd_5x_options(Rec, Opts, T)
    end;
process_cmd_5x_options(_Rec, _Opts, [{message_type, Type}|_T]) ->
    {error, {invalid_option_value, {message_type, Type}}};
process_cmd_5x_options(_Rec, _Opts, [H|_T]) ->
    {error, {unknown_option, H}}.

get_message_types() ->
    [text, unicode_text, binary, binary_stk].

apply_message_type(unicode_text, Body) ->
    Body#ucp_cmd_5x{
              mt = "4",
              xser = "020108"};
apply_message_type(binary, Body) ->
    Body#ucp_cmd_5x{
              mt = "4"};
apply_message_type(binary_stk, Body) ->
    Body#ucp_cmd_5x{
              rpid = "0127",
              mcls = "2", %% class 2: message stored on the SIM
              mt = "4", %% transparent data
              xser = "01030270000201F60D0101", %% UDH with 7000 (STK)
              pr = "0"};
apply_message_type(_Other, Body) ->
    % Do nothing
    Body.

%%--------------------------------------------------------------------
%% Create body of UCP 60 - loging message
%%--------------------------------------------------------------------
create_cmd_60_body(Login,  Password) ->
    IRAPassword = lists:flatten(ucp_utils:to_hexstr(ucp_ira:to(ira, Password))),
    Body = #ucp_cmd_60{
              oadc = Login,
              oton = "6",
              onpi = "5",
              styp = "1",
              pwd = IRAPassword,
              vers = "0100"},
    {cmd_body, "60", Body}.

%%--------------------------------------------------------------------
%% Create body of UCP 31 - alert message / used for keep-alive
%%--------------------------------------------------------------------
create_cmd_31_body(Address) ->
    Body = #ucp_cmd_31{
              adc = Address,
              pid = "0539"},
    {cmd_body, "31", Body}.

%%--------------------------------------------------------------------
%% Create body of ACK message
%%--------------------------------------------------------------------
create_ack(Header) when is_record(Header, ucp_header) ->
    {ok, ucp_utils:compose_message(Header#ucp_header{o_r = "R"}, #ack{})}.

%%--------------------------------------------------------------------
%% Message splitting
%%--------------------------------------------------------------------
split_message(CRef, XSer, Message) when is_binary(Message) ->
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
                    add_concat_info(CRef, Result, proplists:delete(1, Services), UDH);
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
            {result, [{ModXSer, Message}], CRef}
    end;

%TODO: check splitting for Text messages
split_message(CRef, XSer, Message) ->
    {result, [{XSer, Message}], CRef}.

add_concat_info(CRef, Bins, Services, UDH) ->
    NextCRef = case length(Bins) > 1 of
                   true -> ucp_utils:get_next_ref(CRef);
                   false -> CRef
               end,
    {result, add_concat_info(NextCRef, Bins, Services, UDH, length(Bins), 1, []), NextCRef}.

add_concat_info(_CRef, [Bin], Services, UDH, Parts, _PartNo, _Result) when Parts =< 1 ->
    {ok, Service1} = udh_to_service(UDH),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    [{XSer, Bin}];
add_concat_info(_CRef, [], _Services, _UDH, _Parts, _PartNo, Result) ->
    lists:reverse(Result);
add_concat_info(CRef, [H|T], Services, UDH, Parts, PartNo, Result) ->
    IE = {0, {info_element, {0, 3, [CRef, Parts, PartNo]}}},
    {ok, Service1} = udh_to_service([IE | UDH]),
    {ok, XSer} = services_to_xser([Service1 | Services]),
    ModUDH = case PartNo of
                1 -> proplists:delete(?STK_IE, UDH);
                _ -> UDH
             end,
    add_concat_info(CRef, T, Services, ModUDH, Parts, PartNo+1, [{XSer, H}|Result]).

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
    xser_to_services(ucp_utils:hexstr_to_list(XSer), []).

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
    {ok, ucp_utils:to_hexstr(lists:flatten(Result))};
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


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                               Eunit Tests                               %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-ifdef (TEST).
-include_lib("eunit/include/eunit.hrl").
decoder_test_() ->
    [
        {"Detect message type",
            [fun detect_type_bin/0,
             fun detect_type_text/0]}
    ].

detect_type_bin() ->
    M = <<0, 12, 123, 34, 9>>,
    ?assertEqual(
        binary, detect_msg_type(M)
    ).

detect_type_text() ->
    M = "test",
    ?assertEqual(
        text, detect_msg_type(M)
    ).

xser_to_services_test() ->
    XSer = "01060500031502020201F6",
    {ok, X} = xser_to_services(XSer),
    ?assertMatch({service, {1, 6, _}}, proplists:get_value(1, X)),
    {ok, NewXSer} = services_to_xser(X),
    ?assertMatch(XSer, NewXSer).

xser_update_test() ->
    XSer = "0201F601080700031502027000",
    {ok, X} = xser_to_services(XSer),
    {ok, Y} = service_to_udh(proplists:get_value(1, X)),
    UDH = proplists:delete(0, Y),
    IE = {0, {info_element, {0, 3, [1, 3, 1]}}},
    {ok, Service1} = udh_to_service([IE | UDH]),
    {ok, NewXSer} = services_to_xser([Service1 | proplists:delete(1, X)]),
    % Same sorted value
    ?assertMatch("010807000301030170000201F6", NewXSer).

udh_size_test() ->
    {ok, X} = xser_to_services("010807000315020170000201F6"),
    {ok, Y} = service_to_udh(proplists:get_value(1, X)),
    ?assertMatch(8, get_udh_size(Y)),
    ?assertMatch(3, get_udh_size(proplists:delete(0, Y))).

parse_udh_test() ->
    {ok, X} = xser_to_services("010807000315020170000201F6"),
    {ok, Y} = service_to_udh(proplists:get_value(1, X)),
    ?assertMatch(8, get_udh_size(Y)),
    ?assertMatch(3, get_udh_size(proplists:delete(0, Y))).

parse_udh_2_test() ->
    {ok, X} = xser_to_services("010807000315020170000201F6"),
    %?debugFmt("~p~n", [X]),
    {ok, Y} = service_to_udh(proplists:get_value(1, X)),
    %?debugFmt("~p~n", [Y]),
    ?assertMatch({info_element, {0, 3, _}}, proplists:get_value(0, Y)).

udh_to_service_test() ->
    {ok, S} = udh_to_service([{112,{info_element,{112,0,[]}}},{0,{info_element,{0,3,[21,2,1]}}}]),
    %?debugFmt("~p~n", [S]),
    ?assertMatch({1, {service, {1, 8, _}}}, S).

check_splitting_one_full_test() ->
    % one sms
    {result, L1, R1} = split_message(0, "", <<0:(140*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(1, length(L1)),
    ?assertMatch(0, R1),
    {result, L2, R2} = split_message(0, "0103027000", <<0:(137*8)>>),
    %?debugFmt("~p~n", [L2]),
    ?assertMatch(1, length(L2)),
    ?assertMatch(0, R2),
    {result, L3, R3} = split_message(0, "010807000315020170000201F6", <<0:(137*8)>>),
    %?debugFmt("~p~n~", [L3]),
    ?assertMatch(1, length(L3)),
    ?assertMatch(0, R3),
    ok.

check_splitting_divided_on_two_test() ->
    % one sms
    {result, L1, R1} = split_message(0, "", <<0:(141*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(2, length(L1)),
    ?assertMatch(1, R1),
    [{A1, B1}, {C1, D1}] = L1,
    ?assertMatch({16,134,16,7}, {length(A1),size(B1),length(C1),size(D1)}),
    % -----
    {result, L2, R2} = split_message(0, "0103027000", <<0:(138*8)>>),
    %?debugFmt("~p~n", [L2]),
    ?assertMatch(2, length(L2)),
    ?assertMatch(1, R2),
    [{A2, B2}, {C2, D2}] = L2,
    ?assertMatch({20,132,16,6}, {length(A2),size(B2),length(C2),size(D2)}),
    %% 2 full sms
    {result, L3, R3} = split_message(0, "", <<0:(268*8)>>),
    %?debugFmt("~p~n", [L3]),
    ?assertMatch(2, length(L3)),
    ?assertMatch(1, R3),
    [{A3, B3}, {C3, D3}] = L3,
    ?assertMatch({16,134,16,134}, {length(A3),size(B3),length(C3),size(D3)}),
    %% 2 full sms
    {result, L4, R4} = split_message(0, "0103027000", <<0:(266*8)>>),
    %?debugFmt("~p~n", [L4]),
    ?assertMatch(2, length(L4)),
    ?assertMatch(1, R4),
    [{A4, B4}, {C4, D4}] = L4,
    ?assertMatch({20,132,16,134}, {length(A4),size(B4),length(C4),size(D4)}),
    % --
    {result, L5, R5} = split_message(0, "010807000315020170000201F6", <<0:(266*8)>>),
    %?debugFmt("~p~n", [L5]),
    ?assertMatch(2, length(L5)),
    ?assertMatch(1, R5),
    [{A5, B5}, {C5, D5}] = L5,
    ?assertMatch({26,132,22,134}, {length(A5),size(B5),length(C5),size(D5)}),
    ok.

check_splitting_divided_on_three_test() ->
    {result, L1, R1} = split_message(0, "", <<0:(269*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(3, length(L1)),
    ?assertMatch(1, R1),
    [{A1, B1}, {C1, D1}, {E1, F1}] = L1,
    ?assertMatch({16,134,16,134,16,1}, {length(A1),size(B1),length(C1),size(D1),length(E1),size(F1)}),
    {result, L4, R4} = split_message(0, "0103027000", <<0:(267*8)>>),
    %?debugFmt("~p~n", [L4]),
    ?assertMatch(3, length(L4)),
    ?assertMatch(1, R4),
    [{A4, B4}, {C4, D4}, {E4, F4}] = L4,
    ?assertMatch({20,132,16,134,16,1}, {length(A4),size(B4),length(C4),size(D4),length(E4),size(F4)}),
    % --
    {result, L5, R5} = split_message(0, "010807000315020170000201F6", <<0:(267*8)>>),
    %?debugFmt("~p~n", [L5]),
    ?assertMatch(3, length(L5)),
    ?assertMatch(1, R5),
    [{A5, B5}, {C5, D5}, {E5, F5}] = L5,
    ?assertMatch({26,132,22,134,22,1}, {length(A5),size(B5),length(C5),size(D5),length(E5),size(F5)}),
    ok.

message_too_long_test() ->
    {result, L1, R1} = split_message(0, "", <<0:(536*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(4, length(L1)),
    ?assertMatch(1, R1),
    R = split_message(0, "", <<0:(537*8)>>),
    ?assertMatch({error, message_too_long}, R).

message_options_test() ->
    Body = #ucp_cmd_5x{},
    % unknown option
    ?assertMatch({error, {unknown_option, {test, 0}}},
        process_cmd_5x_options(Body, [{test, 0}])),
    % invalid option value
    ?assertMatch({error, {invalid_option_value, {notification_request, _}}},
        process_cmd_5x_options(Body, [{notification_request, "not_bool"}])),
    % notification disabled
    ?assertMatch({ok, Body},
        process_cmd_5x_options(Body, [{notification_request, false}])),
    % notification enabled
    B2 = Body#ucp_cmd_5x{nrq = "1", npid = "0539", nt = "3"},
    ?assertMatch({ok, B2},
        process_cmd_5x_options(Body, [{notification_request, true}])),
    % default notification type override
    B3 = B2#ucp_cmd_5x{nt = "7"},
    ?assertMatch({ok, B3},
        process_cmd_5x_options(Body, [{notification_request, true},
                                                 {notification_type, 7}])),
    % notification_type invalid value
    ?assertMatch({error, {invalid_option_value, {notification_type, _}}},
        process_cmd_5x_options(Body, [{notification_request, true},
                                                 {notification_type, 10}])),
    ?assertMatch({error, {invalid_option_value, {notification_type, _}}},
        process_cmd_5x_options(Body, [{notification_request, true},
                                                 {notification_type, asdf}])),
    ?assertMatch({error, {invalid_option_value, {notification_type, _}}},
        process_cmd_5x_options(Body, [{notification_request, true},
                                                 {notification_type, "sdf"}])),
    ok.

-endif.
