-module(ucp_conn_pool).

-behaviour(gen_server).

-include("logger.hrl").

%% API
-export([start_link/0,
         get_members/0,
         join_pool/1,
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

-type alive_conns() :: [{atom(), pid()}] | [].
-type pool_config() :: [{atom(), tuple()}] | [].
-type newborns() :: pool_config().
-type convicts() :: alive_conns().

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

health_check() ->
    gen_server:call(?SERVER, health_check).

get_members() ->
    gen_server:call(?SERVER, get_members).

join_pool(Pid) when is_pid(Pid) ->
    gen_server:call(?SERVER, {join_pool, Pid}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    pg2:create(?POOL_NAME),
    confetti:use(ucp_pool_conf, [
            {location, {"ucp_pool_conf.conf", "conf"}},
            {validators, [fun ensure_valid_syntax/1,
                          fun ensure_conn_names_unique/1]}
        ]),
    Conns = confetti:fetch(ucp_pool_conf),
    {ok, #state{endpoints = Conns}, 0}.

handle_call(get_members, _From, State) ->
    Reply = get_members_internal(),
    {reply, Reply, State};

handle_call({join_pool, Pid}, _From, State) ->
    case lists:member(Pid, get_members_internal()) of
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
    resurrect_newborns(Endpoints),
    {noreply, State};

handle_info({config_reloaded, Conf}, State) ->
    ?SYS_INFO("UCP Connection pool received configuration change
        notification...", []),
    ?SYS_DEBUG("New configuration: ~p", [Conf]),
    { {convicts, C}, {newborns, N} } = qualify_conns_destiny(Conf),
    kill_convicts(C),
    resurrect_newborns(N),
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

connect_smsc({Name, {Host, Port, Login, Password, up}}) ->
   % TODO: handle errors
   {ok, _Pid} = ucp_conn_sup:start_child({Name, {Host, Port, Login, Password}}),
   ok;

connect_smsc({Name, {_Host, _Port, _Login, _Password, State}}) ->
   ?SYS_DEBUG("Connection ~p excluded from starting, due to its status: ~p", [Name, State]),
   ok.

get_members_internal() ->
    pg2:get_local_members(?POOL_NAME).

%%%===================================================================
%%% Configuration reload handlers
%%%===================================================================

kill_convicts([]) -> ?SYS_DEBUG("No unused connections found...", []);
kill_convicts(C) when is_list(C) ->
    ?SYS_INFO("Found unused connection(s): ~p", [C]),
    lists:foreach(fun({Name, Pid}) ->
                Res = ucp_conn:close(Pid),
                ?SYS_INFO("Killing ~p... ~p", [{Name,Pid}, Res])
                end, C).

resurrect_newborns([]) -> ?SYS_DEBUG("No new connections to estabilish...", []);
resurrect_newborns(N) when is_list(N) ->
    ?SYS_INFO("Found new connection(s) to estabilish: ~p", [N]),
    lists:foreach(fun connect_smsc/1, N).

is_conn_alive(Name, ConnsAlive) ->
    lists:member(Name, [ CName || {CName, _} <- ConnsAlive ]).

-spec find_convicts(alive_conns(), pool_config()) -> convicts().

find_convicts(ConnsAlive, []) -> ConnsAlive;
find_convicts(ConnsAlive, Conf) ->
    lists:filter(fun({Name, _}) ->
                {_,_,_,_,Status} = proplists:get_value(Name, Conf),
                %% find oprhans
                not lists:member(Name, proplists:get_keys(Conf))
                %% find explicit shutdowns
                or (Status =:= down)
        end, ConnsAlive).

-spec find_newborns(alive_conns(), pool_config()) -> newborns().

find_newborns(_, []) -> [];
find_newborns(ConnsAlive, Conf) ->
    lists:filter(fun({Name,{_,_,_,_,Status}}) ->
                case Status of
                    up -> not is_conn_alive(Name, ConnsAlive);
                    down -> false
                end
        end, Conf).

-spec find_chameleons(alive_conns(), pool_config()) ->
    { {c, convicts()}, {n, newborns()} } | undefined.

find_chameleons(_, []) -> undefined;
find_chameleons([], _) -> undefined;
find_chameleons(ConnsAlive, Conf) ->
    Newborns = lists:filter(fun({Name,_} = ConfProp) ->
                case is_conn_alive(Name, ConnsAlive) of
                    true ->
                        {conf, C} = ucp_conn:get_reverse_config(
                                        proplists:get_value(Name, ConnsAlive)),
                        C =/= ConfProp;
                    false -> false
                end
        end, [ Conn || {_,{_,_,_,_,Status}} = Conn <- Conf, Status =:= up ]),
    case Newborns of
        [] -> undefined;
        Nborns when is_list(Nborns) ->
            Convicts = lists:map(fun({Name, _Newborn}) ->
                        proplists:lookup(Name, ConnsAlive)
                end, Nborns),
            {{c,Convicts},{n,Nborns}}
    end.

-spec qualify_conns_destiny(pool_config()) ->
    {{convicts, convicts()}, {newborns, newborns()}}.

qualify_conns_destiny(Conf) ->
    %% get alive connections, at least according to the pg2 pool
    ConnsAlive = lists:map(fun(Pid) ->
                        {name, N} = ucp_conn:get_name(Pid),
                        {N, Pid}
                 end, get_members_internal()),
    ?SYS_DEBUG("Connection processes alive: ~p", [ConnsAlive]),
    Convicts = find_convicts(ConnsAlive, Conf),
    Newborns = find_newborns(ConnsAlive, Conf),
    Chameleons = find_chameleons(ConnsAlive, Conf),
    ?SYS_DEBUG("Convicts: ~p", [Convicts]),
    ?SYS_DEBUG("Newborns: ~p", [Newborns]),
    ?SYS_DEBUG("Chameleons: ~p", [Chameleons]),
    case Chameleons of
        undefined  ->
            { {convicts, Convicts}, {newborns, Newborns} };
        {{c,ChConvicts},{n,ChNewborns}} ->
            { {convicts, ChConvicts ++ Convicts},
              {newborns, ChNewborns ++ Newborns} }
    end.

ensure_conn_names_unique(Conf) ->
    Names = lists:usort(proplists:get_keys(Conf)),
    case length(Names) =:= length(Conf) of
        true -> {ok, Conf};
        false -> {error, {ucp_pool_conf, "Connections names must be unique"}}
    end.

ensure_valid_syntax(Conf) ->
    try
        lists:foreach(fun(Term) ->
                    case Term of
                        {Name, {Host, Port, Login, Pass, Status}} when
                            is_atom(Name),
                            is_atom(Host) orelse is_list(Host),
                            is_integer(Port),
                            is_list(Login),
                            is_list(Pass),
                            Status =:= up orelse Status =:= down ->
                                ok;
                        _ ->
                            throw({badmatch, Term})
                    end
            end, Conf) of
                _ -> {ok, Conf}
        catch _Class:Error -> {error, Error}
    end.




