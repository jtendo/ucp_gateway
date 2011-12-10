-module(ucp_messages_tests).
-compile([export_all]).

-include_lib("eunit/include/eunit.hrl").
-include("ucp_syntax.hrl").

parse_xser_to_services_test() ->
    XSer = "01060500031502020201F6",
    {ok, X} = ucp_messages:xser_to_services(XSer),
    ?assertMatch({service, {1, 6, _}}, proplists:get_value(1, X)),
    {ok, NewXSer} = ucp_messages:services_to_xser(X),
    ?assertMatch(XSer, NewXSer).

xser_update_test() ->
    XSer = "0201F601080700031502027000",
    {ok, X} = ucp_messages:xser_to_services(XSer),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    UDH = proplists:delete(0, Y),
    IE = {0, {info_element, {0, 3, [1, 3, 1]}}},
    {ok, Service1} = ucp_messages:udh_to_service([IE | UDH]),
    {ok, NewXSer} = ucp_messages:services_to_xser([Service1 | proplists:delete(1, X)]),
    % Same sorted value
    ?assertMatch("010807000301030170000201F6", NewXSer).

udh_size_test() ->
    {ok, X} = ucp_messages:xser_to_services("010807000315020170000201F6"),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    ?assertMatch(8, ucp_messages:get_udh_size(Y)),
    ?assertMatch(3, ucp_messages:get_udh_size(proplists:delete(0, Y))).

parse_udh_test() ->
    {ok, X} = ucp_messages:xser_to_services("010807000315020170000201F6"),
    %?debugFmt("~p~n", [X]),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    %?debugFmt("~p~n", [Y]),
    ?assertMatch({info_element, {0, 3, _}}, proplists:get_value(0, Y)).

udh_to_service_test() ->
    {ok, S} = ucp_messages:udh_to_service([{112,{info_element,{112,0,[]}}},{0,{info_element,{0,3,[21,2,1]}}}]),
    %?debugFmt("~p~n", [S]),
    ?assertMatch({1, {service, {1, 8, _}}}, S).

check_splitting_one_full_test() ->
    % one sms
    {result, L1, R1} = ucp_messages:split_message(0, "", <<0:(140*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(1, length(L1)),
    ?assertMatch(0, R1),
    {result, L2, R2} = ucp_messages:split_message(0, "0103027000", <<0:(137*8)>>),
    %?debugFmt("~p~n", [L2]),
    ?assertMatch(1, length(L2)),
    ?assertMatch(0, R2),
    {result, L3, R3} = ucp_messages:split_message(0, "010807000315020170000201F6", <<0:(137*8)>>),
    %?debugFmt("~p~n~", [L3]),
    ?assertMatch(1, length(L3)),
    ?assertMatch(0, R3),
    ok.

check_splitting_divided_on_two_test() ->
    % one sms
    {result, L1, R1} = ucp_messages:split_message(0, "", <<0:(141*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(2, length(L1)),
    ?assertMatch(1, R1),
    [{A1, B1}, {C1, D1}] = L1,
    ?assertMatch({16,134,16,7}, {length(A1),size(B1),length(C1),size(D1)}),
    % -----
    {result, L2, R2} = ucp_messages:split_message(0, "0103027000", <<0:(138*8)>>),
    %?debugFmt("~p~n", [L2]),
    ?assertMatch(2, length(L2)),
    ?assertMatch(1, R2),
    [{A2, B2}, {C2, D2}] = L2,
    ?assertMatch({20,132,16,6}, {length(A2),size(B2),length(C2),size(D2)}),
    %% 2 full sms
    {result, L3, R3} = ucp_messages:split_message(0, "", <<0:(268*8)>>),
    %?debugFmt("~p~n", [L3]),
    ?assertMatch(2, length(L3)),
    ?assertMatch(1, R3),
    [{A3, B3}, {C3, D3}] = L3,
    ?assertMatch({16,134,16,134}, {length(A3),size(B3),length(C3),size(D3)}),
    %% 2 full sms
    {result, L4, R4} = ucp_messages:split_message(0, "0103027000", <<0:(266*8)>>),
    %?debugFmt("~p~n", [L4]),
    ?assertMatch(2, length(L4)),
    ?assertMatch(1, R4),
    [{A4, B4}, {C4, D4}] = L4,
    ?assertMatch({20,132,16,134}, {length(A4),size(B4),length(C4),size(D4)}),
    % --
    {result, L5, R5} = ucp_messages:split_message(0, "010807000315020170000201F6", <<0:(266*8)>>),
    %?debugFmt("~p~n", [L5]),
    ?assertMatch(2, length(L5)),
    ?assertMatch(1, R5),
    [{A5, B5}, {C5, D5}] = L5,
    ?assertMatch({26,132,22,134}, {length(A5),size(B5),length(C5),size(D5)}),
    ok.

check_splitting_divided_on_three_test() ->
    {result, L1, R1} = ucp_messages:split_message(0, "", <<0:(269*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(3, length(L1)),
    ?assertMatch(1, R1),
    [{A1, B1}, {C1, D1}, {E1, F1}] = L1,
    ?assertMatch({16,134,16,134,16,1}, {length(A1),size(B1),length(C1),size(D1),length(E1),size(F1)}),
    {result, L4, R4} = ucp_messages:split_message(0, "0103027000", <<0:(267*8)>>),
    %?debugFmt("~p~n", [L4]),
    ?assertMatch(3, length(L4)),
    ?assertMatch(1, R4),
    [{A4, B4}, {C4, D4}, {E4, F4}] = L4,
    ?assertMatch({20,132,16,134,16,1}, {length(A4),size(B4),length(C4),size(D4),length(E4),size(F4)}),
    % --
    {result, L5, R5} = ucp_messages:split_message(0, "010807000315020170000201F6", <<0:(267*8)>>),
    %?debugFmt("~p~n", [L5]),
    ?assertMatch(3, length(L5)),
    ?assertMatch(1, R5),
    [{A5, B5}, {C5, D5}, {E5, F5}] = L5,
    ?assertMatch({26,132,22,134,22,1}, {length(A5),size(B5),length(C5),size(D5),length(E5),size(F5)}),
    ok.

message_too_long_test() ->
    {result, L1, R1} = ucp_messages:split_message(0, "", <<0:(536*8)>>),
    %?debugFmt("~p~n", [L1]),
    ?assertMatch(4, length(L1)),
    ?assertMatch(1, R1),
    R = ucp_messages:split_message(0, "", <<0:(537*8)>>),
    ?assertMatch({error, message_too_long}, R).

message_options_test() ->
    Body = #ucp_cmd_5x{},
    % unknown option
    ?assertMatch({error, unknown_option},
        ucp_messages:check_cmd_5x_options(Body, [{test, 0}])),
    ok.
