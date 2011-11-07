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
    {ok, Pid} = supervisor:start_child(?SERVER, [Conf]),
    ucp_conn_pool:join_pool(Pid),
    {ok, Pid}.

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

%% A permanent process should always be restarted, no matter what.
%% We don't need the supervisor restart processes that were explicitly shut
%% down (i.e. orphan connections kill).

init([]) ->
    Worker = {ucp_conn, {ucp_conn, start_link, []}, transient, brutal_kill, worker, [ucp_conn]},
    {ok, {{simple_one_for_one, 10, 60}, [Worker]}}.

