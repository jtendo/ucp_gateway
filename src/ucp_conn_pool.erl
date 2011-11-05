-module(ucp_conn_pool).

-behaviour(gen_server).

-include("logger.hrl").

%% API
-export([start_link/0,
         get_members/0,
         join_pool/0,
         health_check/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).
-define(POOL_NAME, ucp_conn_pool).

-record(state, {endpoints}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

health_check() ->
    gen_server:call(?SERVER, health_check).

get_members() ->
    gen_server:call(?SERVER, get_members).

join_pool() ->
    gen_server:call(?SERVER, {join_pool}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    pg2:create(?POOL_NAME),
    confetti:use(ucp_pool_conf),
    Conns = confetti:fetch(ucp_pool_conf),
    {ok, #state{endpoints = Conns}, 0}.

handle_call(get_members, _From, State) ->
    Reply = get_members_internal(),
    {reply, Reply, State};

handle_call({join_pool}, {Pid, _}, State) ->
    case lists:member(Pid, pg2:get_local_members(?POOL_NAME)) of
        true -> ok;
        false ->
            pg2:join(?POOL_NAME, Pid)
    end,
    {reply, ok, State};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(timeout, #state{endpoints = Endpoints} = State) ->
    lists:map(fun connect_smsc/1, Endpoints),
    {noreply, State};

handle_info({config_reloaded, Conf}, State) ->
    ?SYS_INFO("UCP Connection pool received configuration change
        notification...", []),
    case find_connections_to_kill(Conf) of
        [] ->
            ?SYS_DEBUG("No unused connections found...", []);
        Orphans when is_list(Orphans) ->
            ?SYS_INFO("Found unused connections: ~p", [Orphans]),
            lists:foreach(fun({Pid, Name}) ->
                        Res = ucp_conn:close(Pid),
                        ?SYS_INFO("Killing ~p... ~p", [{Pid,Name}, Res])
                end, Orphans)
    end,
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

connect_smsc({Name, Host, Port, Login, Password, up}) ->
   % TODO: handle errors
   {ok, _Pid} = ucp_conn_sup:start_child({Name, Host, Port, Login, Password}),
   ok;

connect_smsc({Name, _Host, _Port, _Login, _Password, State}) ->
   ?SYS_DEBUG("Connection ~p excluded from starting, due to its status: ~p", [Name, State]),
   ok.

get_members_internal() ->
    pg2:get_local_members(?POOL_NAME).

find_connections_to_kill(Conf) ->
    %% get alive connections, at least according to the pg2 pool
    ConnsAlive = lists:map(fun(Pid) ->
                        {Pid, ucp_conn:get_name(Pid)}
                 end, get_members_internal()),
    %% get raw connection names from configuration
    ConfNames = [ N || {N,_,_,_,_,_,_} <- Conf ],
    %% get raw connection names that are explicitly told to be shut down
    ConfsToShutdown = [ N || {N,_,_,_,_,Status} <- Conf, Status =:= down ],
    ?SYS_DEBUG("Connection names configured: ~p", [ConfNames]),
    %% filter out connections that are not configured or need to be shut down
    Convicts = lists:filter(fun({_, {name, Name}}) ->
        not lists:member(Name, ConfNames)
        or lists:member(Name, ConfsToShutdown)
    end, ConnsAlive),
    ?SYS_DEBUG("Convicted connections: ~p", [Convicts]),
    Convicts.
