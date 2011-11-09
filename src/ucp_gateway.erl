-module(ucp_gateway).

-behaviour(application).

%% Application callbacks
-export([start/0, start/2, stop/1]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

start(_StartType, _StartArgs) ->
    ets:new(sms, [public, named_table]),
    ets:insert(sms, {cntr, 0}),
    ucp_gateway_sup:start_link().

% For application start from console
start() ->
    application:start(ucp_gateway).

stop(_State) ->
        ok.

