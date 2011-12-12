-module(ucp_utils_tests).
-author('adam.rutkowski@jtendo.com').
-compile([export_all]).

-include_lib("eunit/include/eunit.hrl").

%% just basic assertions to prevent regression

split_join_test() ->
    L = "ABC/DEF/GHI",
    R = ucp_utils:ucp_split(L),
    ?assertEqual(["ABC", "DEF", "GHI"], R),
    L2 = ucp_utils:ucp_join(R, R),
    ?assertEqual("ABC/DEF/GHI/ABC/DEF/GHI", L2),
    L3 = ucp_utils:ucp_join(R, R, append),
    ?assertEqual("ABC/DEF/GHI/ABC/DEF/GHI/", L3),
    R2 = ucp_utils:ucp_split(L3),
    ?assertEqual(["ABC", "DEF", "GHI", "ABC", "DEF", "GHI", []], R2),
    R3 = ucp_utils:ucp_split("///"),
    ?assertEqual([[],[],[],[]], R3).

rv_test() ->
    A = {foo, bar, baz},
    B = {foo, [bar, {baz}]},
    ?assertEqual([bar, baz], ucp_utils:rv(A)),
    ?assertEqual([[bar, {baz}]], ucp_utils:rv(B)).

encode_sender_test() ->
    ?assertEqual({"", "1112376382900"}, ucp_utils:encode_sender("1112376382900")),
    ?assertEqual({"5039", "106F79D87D2EBBE06C"}, ucp_utils:encode_sender("orange.pl")),
    ?assertEqual("orange.pl", ucp_utils:decode_sender("5039", "106F79D87D2EBBE06C")),
    ?assertEqual("11112376382900", ucp_utils:decode_sender(whatever, "11112376382900")),
    ?assertEqual({"5039", "2721E08854F29A54A854ABB7DA76F77DEECBC5D201"},
        ucp_utils:encode_sender("!@#$%^&*()-=+[]{}\\/.,:")),
    ?assertEqual("!@#$%^&*()-=+[]{}\\/.,:", ucp_utils:decode_sender("5039",
        "2721E08854F29A54A854ABB7DA76F77DEECBC5D201")).


