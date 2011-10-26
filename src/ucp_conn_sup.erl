-module(ucp_conn_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_child/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_child(Conf) ->
    supervisor:start_child(?SERVER, [Conf]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    Worker = {ucp_conn, {ucp_conn, start_link, []}, permanent, brutal_kill, worker, [ucp_conn]},
    {ok, {{simple_one_for_one, 10, 60}, [Worker]}}.

