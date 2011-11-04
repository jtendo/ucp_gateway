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

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    pg2:create(?POOL_NAME),
    confetti:use(ucp_pool_conf),
    Conns = confetti:fetch(ucp_pool_conf),
    {ok, #state{endpoints = Conns}, 0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(get_members, _From, State) ->
    Reply = pg2:get_local_members(?POOL_NAME),
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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(timeout, #state{endpoints = Endpoints} = State) ->
    lists:map(fun connect_smsc/1, Endpoints),
    {noreply, State};

handle_info(_Info, State) ->
        {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
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

