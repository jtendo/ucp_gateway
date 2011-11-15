-module(ucp_messages_tests).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).

parse_xser_to_services_test() ->
    XSer = "01060500031502020201F6",
    {ok, X} = ucp_messages:xser_to_services(XSer),
    ?assertMatch({service, {1, 6, _}}, proplists:get_value(1, X)),
    {ok, NewXSer} = ucp_messages:services_to_xser(X),
    ?assertMatch(XSer, NewXSer).

xser_update_test() ->
    XSer = "010807000315020270000201F6",
    {ok, X} = ucp_messages:xser_to_services(XSer),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    UDH = proplists:delete(0, Y),
    IE = {0, {info_element, {0, 3, [1, 3, 1]}}},
    {ok, Service1} = ucp_messages:udh_to_service([IE | UDH]),
    {ok, NewXSer} = ucp_messages:services_to_xser([Service1 | proplists:delete(1, X)]),
    ?assertMatch("0201F601080770000003010301", NewXSer).

udh_size_test() ->
    {ok, X} = ucp_messages:xser_to_services("010807000315020170000201F6"),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    ?assertMatch(8, ucp_messages:get_udh_size(Y)),
    ?assertMatch(3, ucp_messages:get_udh_size(proplists:delete(0, Y))).

parse_udh_test() ->
    {ok, X} = ucp_messages:xser_to_services("010807000315020170000201F6"),
    ?debugFmt("~p~n", [X]),
    {ok, Y} = ucp_messages:service_to_udh(proplists:get_value(1, X)),
    ?debugFmt("~p~n", [Y]),
    ?assertMatch({info_element, {0, 3, _}}, proplists:get_value(0, Y)).

udh_to_service_test() ->
    {ok, S} = ucp_messages:udh_to_service([{112,{info_element,{112,0,[]}}},{0,{info_element,{0,3,[21,2,1]}}}]),
    ?debugFmt("~p~n", [S]),
    ?assertMatch({1, {service, {1, 8, _}}}, S).

check_splitting_one_full_test() ->
    % one sms
    {result, R1} = ucp_messages:split_message(<<0:(140*8)>>, "", 255),
    %?debugFmt("~p~n", [R1]),
    ?assertMatch(1, length(R1)),
    {result, R2} = ucp_messages:split_message(<<0:(137*8)>>, "0103027000", 255),
    %?debugFmt("~p~n", [R2]),
    ?assertMatch(1, length(R2)),
    ok.

check_splitting_divided_on_two_test() ->
    % one sms
    {result, R1} = ucp_messages:split_message(<<0:(141*8)>>, "", 255),
    %?debugFmt("~p~n", [R1]),
    ?assertMatch(2, length(R1)),
    {result, R2} = ucp_messages:split_message(<<0:(138*8)>>, "0103027000", 255),
    ?debugFmt("~p~n", [R2]),
    ?assertMatch(2, length(R2)),
    % 2 full sms
    {result, R3} = ucp_messages:split_message(<<0:(268*8)>>, "0103027000", 255),
    ?debugFmt("~p~n", [R3]),
    ?assertMatch(2, length(R3)),
    %{result, R2} = ucp_messages:split_message(<<0:(132*8)>>, [{extra_services,
                                                               %"01030270000201F6"}]),
    %?debugFmt("~p~n", [R2]),
    %?assertMatch(1, length(R2)),
    %{result, R3} = ucp_messages:split_message(<<0:(132*8)>>, [{extra_services,
                                                               %"010807000315020170000201F6"}]),
    %?debugFmt("~p~n", [R3]),
    %?assertMatch(1, length(R3)),
    %{result, R4} = ucp_messages:split_message(<<0:(128*8)>>, [{extra_services,
                                                               %"01070670000402F0FA0201F6"}]),
    %?debugFmt("~p~n", [R4]),
    %?assertMatch(1, length(R4)),
    ok.

check_splitting_divided_on_three_test() ->
    {result, R1} = ucp_messages:split_message(<<0:(269*8)>>, "0103027000", 255),
    ?debugFmt("~p~n", [R1]),
    ?assertMatch(3, length(R1)),
    ok.

message_too_long_test() ->
    R = ucp_messages:split_message(<<0:(541*8)>>, [], 255),
    ?assertMatch({error, message_too_long}, R).

