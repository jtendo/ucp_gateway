-module(ucp_event).
-author('andrzej.trawinski@jtendo.com').
-author('adam.rutkowski@jtendo.com').

%% API
-export([start_link/0, add_handler/1]).

-define(SERVER, ?MODULE).

start_link() ->
    gen_event:start_link({local, ?SERVER}).

add_handler(Module) ->
    gen_event:add_handler(?SERVER, Module, []).


