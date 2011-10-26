%%%-------------------------------------------------------------------
%%% @author Rafał Gałczyński <rafal.galczynski@gmail.com>
%%% @copyright (C) 2011, Rafał Gałczyński
%%% @doc
%%%
%%% @end
%%% Created :  7 Apr 2011 by Rafał Gałczyński <rafal.galczynski@gmail.com>
%%%-------------------------------------------------------------------
-module(smsc_pool).

-behaviour(gen_server).
-include_lib("stdlib/include/qlc.hrl").

-include("../include/smsc_retry.hrl").
-include("../include/logger.hrl").
-include("../include/utils.hrl").

%% API
-export([
         start_link/0
        ]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, send_message/3, rebuild_pool/0,
         get_state/0, replace_config/1, health_check/0, smsc_retry_find/1,
         dump_actual_config/0, load_config/0]).

-define(SERVER, ?MODULE).
-define(POOL_NAME, "smsc_pool").
-record(state, {
          smsc_config %% actual smsc configuration
         }).

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

get_state() ->
    gen_server:call(?SERVER, get_state).

replace_config(NewConf) ->
    gen_server:call(?SERVER, {replace_config, NewConf}).

dump_actual_config() ->
    gen_server:call(?SERVER, dump_actual_config).

health_check() ->
    gen_server:call(?SERVER, health_check).

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
    case load_config() of
        {ok, SMSCList} ->
            ?SYS_DEBUG("~p", ["Initializing SMSC POOL"]),
            gen_server:cast(?SERVER, {start_links, SMSCList}),
            ?SYS_DEBUG("~p", ["Initializing SMSC POOL finished"]),
            State = #state{smsc_config = SMSCList},
            {ok, State};
        {error, Reason} ->
            ?SYS_ERROR("~p", ["Error in SMSC Pool configuration file, exiting!!"]),
            {stop, Reason}
    end.
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

handle_call({send_sms, {Receiver, Message, ReqId}}, _From, State) ->
    ?SYS_DEBUG("~p", ["Received send_sms call"]),
    Reply = send_message(Receiver, Message, ReqId),
    {reply, Reply, State};

handle_call(dump_actual_config, _From, State) ->
    ?SYS_DEBUG("~p", ["Dumping smsc_pool actual config"]),
    Reply = fs_utils:dump("smsc_pool.conf",State#state.smsc_config),
    {reply, Reply, State};

handle_call(rebuild_pool, _From, State) ->
    ?SYS_DEBUG("~p", ["Received rebuild call"]),
    case load_config() of
        {ok, SMSCConfig} ->
            %% dump of actual configuration
            fs_utils:dump("smsc_pool.conf",State#state.smsc_config),
            %% loading new config
            NewState = State#state{smsc_config = SMSCConfig},
            Reply = do_rebuild_pool(SMSCConfig),
            {reply, Reply, NewState};
        {error, _Reason} ->
            ?SYS_ERROR("~p", ["Error in SMSC Pool configuration file, ignoring"]),
            {reply, {error, smsc_pool_conf_corrupted}, State}
    end;

handle_call(get_state, _From, State) ->
    ?SYS_DEBUG("~p", ["Received get state call"]),
    {reply, State#state.smsc_config, State};

handle_call({replace_config, NewConf}, _From, State) ->
    ?SYS_DEBUG("~p", ["Received replace notification templates"]),
    %% dump of actual configuration
    ok = fs_utils:unconsult(?PRIV("smsc_pool.conf"), NewConf),
    {reply, ok, State};

handle_call(health_check, _From, State) ->
    ConnMeta = lists:foldl(
                 fun(Elem, Acc) ->
                         Name = gen_server:call(Elem,get_name),
                         [Name|Acc]
                 end,
                 [],
                 pg2:get_members(?POOL_NAME)),
    Fun = fun(Atom, Acc) -> atom_to_list(Atom)++" ok; "++Acc end,
    Reply = lists:foldl(Fun, [], ConnMeta),
    {reply, Reply, State};


handle_call(_Request, _From, State) ->
    ?SYS_DEBUG("~p", ["Received unknow call"]),
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

handle_cast({send_sms, {Receiver, Message, ReqId}}, State) ->
    ?SYS_DEBUG("~p", ["Received send_sms cast"]),
    send_message(Receiver, Message, ReqId),
    {noreply, State};

handle_cast({start_links, SMSCList}, State) ->
    ?SYS_DEBUG("~p", ["Received start_links cast"]),
    lists:foreach(
      fun({UName, Host, Port, Login, Password, ConnState}) ->
              case ConnState of
                  up ->
                      %% start_connection(Host, Port, Login, Password, UName);
                      spawn(fun () -> start_connection(Host, Port, Login, Password, UName) end);
                  Else ->
                      ?SYS_DEBUG("Not starting connection (~p), state is ~p", [UName, Else])
              end
      end, SMSCList),
    {noreply, State};

handle_cast(_Msg, State) ->
    ?SYS_DEBUG("~p", ["Received unknow cast"]),
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

write(Rec) ->
    Fun = fun() ->
                  mnesia:write(Rec)
          end,
    mnesia:transaction(Fun).

do(Q) ->
    F = fun() -> qlc:e(Q) end,
    {atomic, Val} = mnesia:transaction(F),
    Val.

smsc_retry_find(ReqId) ->
    do( qlc:q(
          [ X || X <- mnesia:table(smsc_retry),
                 X#smsc_retry.reqid =:= ReqId ]
         )).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function used to sends sms messages
%% @spec do_request({Fun, Args}, Int) ->
%%                                                     ok | Error
%%
%% @end
%%--------------------------------------------------------------------

do_request({_F, Args}, 0) ->
    {Receiver, Message, ReqId} = Args,
    ?SYS_ERROR("~s| Error sending message: ~p to ~p",[ReqId, Message, Receiver]),
    case smsc_retry_find(ReqId) of
        [_Rec] ->
            {error, message_already_in_retry_table};
        [] ->
            Rec = #smsc_retry{ receiver = Receiver,
                               message = Message,
                               reqid = ReqId,
                               first_fail = erlang:localtime()
                             },

            ?SYS_DEBUG("~s| Trying to store message: ~p to ~p",[ReqId, Rec#smsc_retry.message, Rec#smsc_retry.receiver]),
            case write(Rec) of
                {atomic, ok} ->
                    ?SYS_DEBUG("~s| Message: ~p to ~p stored in mnesia",[ReqId, Rec#smsc_retry.message, Rec#smsc_retry.receiver]);
                {aborted, {no_exists, smsc_retry}} ->
                    ?SYS_ERROR("~s| Message: ~p to ~p NOT stored in mnesia",[ReqId, Rec#smsc_retry.message, Rec#smsc_retry.receiver])
            end,
            {error, message_saved_in_retry_table}

    end;

do_request({F, {Receiver, Message, ReqId}}, RetryCount) ->
    case pg2:get_closest_pid(?POOL_NAME) of
        Pid when is_pid(Pid) ->
            case gen_server:call(Pid, {F, {Receiver, Message, ReqId}}) of
                ok ->
                    ?SYS_DEBUG("~s| SMS sent to ~p", [ReqId, Receiver]);
                error ->
                    ?SYS_ERROR("~p", ["error sending trying via different connection"]),
                    do_request({F, {Receiver, Message, ReqId}}, RetryCount-1);
                Opps ->
                    ?SYS_ERROR("Opps -> ~p",[Opps])
            end,
            {ok,ok};
        Err ->
            ?SYS_DEBUG("Error getting connection from pool -> ~p",[Err]),
            {error, Err}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function used to sends sms messages
%% @spec send_message(Receiver, Message, ReqId) -> {ok} | Error
%%
%% @end
%%--------------------------------------------------------------------

send_message(Receiver, Message, ReqId) when is_list(Message)->
    PoolSize = length(pg2:get_members(?POOL_NAME)),
    do_request({send_message,
                {Receiver, Message, ReqId}}, PoolSize);

send_message(Receiver, Message, ReqId) when is_binary(Message)->
    PoolSize = length(pg2:get_members(?POOL_NAME)),
    do_request({send_binary_message,
                {Receiver, Message, ReqId}}, PoolSize).


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function loads new config from file
%% @spec load_config(filename) -> {ok, SMSConfig } | {error, Reason }
%%
%% @end
%%--------------------------------------------------------------------

load_config(Filename) ->
    ?SYS_INFO("Loading SMSC pool configuration: ~s", [Filename]),
    case file:consult(?PRIV(Filename)) of
        {ok, SMSCConf} ->
            ValidConfig = lists:map(
                            fun(ConfLine) ->
                                    case validate(ConfLine) of
                                        {ok, ValidLine} ->
                                            ValidLine;
                                        error ->
                                            {error, smsc_pool_config_corrupted}
                                    end
                            end,
                            SMSCConf),
            case lists:member({error, smsc_pool_config_corrupted}, ValidConfig) of
                true ->
                    {error, smsc_pool_config_corrupted};
                false ->
                    {ok, ValidConfig}
            end;
        {error, Reason} ->
            ?SYS_FATAL("Error loading configuration file (~s): ~p", [Filename, Reason]),
            {error, smsc_pool_config_corrupted}
    end.

load_config() ->
    case load_config("smsc_pool.conf") of
        {ok, SMSConfig} ->
            {ok, SMSConfig};
        {error,  Reason} ->
            ?SYS_FATAL("Error loading configuration file (~s): ~p", ["smsc_pool.conf", Reason]),
            {error, smsc_pool_config_corrupted}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function validates configuration file
%% @spec validate({UName, Host, Port, Login, Password, up}) ->
%%    {ok, {UName, Host, Port, Login, Password, up}} |
%%    {ok, {UName, Host, Port, Login, Password, down}} |
%%    error
%%
%% @end
%%--------------------------------------------------------------------

validate({UName, Host, Port, Login, Password, up}) when
      is_atom(UName),
      is_list(Host),
      is_integer(Port),
      is_list(Login),
      is_list(Password) ->
    {ok, {UName, Host, Port, Login, Password, up}};

validate({UName, Host, Port, Login, Password, down}) when
      is_atom(UName),
      is_list(Host),
      is_integer(Port),
      is_list(Login),
      is_list(Password) ->
    {ok, {UName, Host, Port, Login, Password, down}};

validate(Oops) ->
    ?SYS_FATAL("Error parsing SMSC pool configuration: ~p", [Oops]),
    error.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function rebuilds actual pool of connections using actual configuration
%%
%% @end
%%--------------------------------------------------------------------
rebuild_pool() ->
    gen_server:call({?SERVER, node()}, rebuild_pool).

do_rebuild_pool(NewConfig) ->
    ConnMeta = lists:foldl(
                 fun(Elem, Acc) ->
                         Name = gen_server:call(Elem,get_name),
                         [Name|Acc]
                 end,
                 [],
                 pg2:get_members(?POOL_NAME)),
    lists:foreach(
      fun(ConfLine) ->
              {UName, _Host, _Port, _Login, _Password, Status} = ConfLine,
              NewConnectionInConfig = lists:member(UName, ConnMeta),
              spawn(fun () -> handle_connection(ConfLine, Status, NewConnectionInConfig) end)
      end, NewConfig),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function starts new smsc connection and adds it into pool
%%
%% @spec start_connection(Host, Port, Login, Password, UName) ->
%%                                         ok | {error, Reason }
%% @end
%%--------------------------------------------------------------------

start_connection(Host, Port, Login, Password, UName) ->
    case catch(smsc_connection:start_link(
                 Host, Port, Login, Password, UName)) of
        {ok, Pid} ->
            case pg2:join(?POOL_NAME, Pid) of
                ok ->
                    ?SYS_DEBUG("SMSC connection (~s) has been added to pool", [UName]),
                    ok;
                {error, Reason} ->
                    ?SYS_DEBUG("Error adding SMSC connection (~s) to pool: ~p", [UName, Reason]),
                    {error, Reason}
            end;
        Error ->
            {error, Error}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function witch decide what to do with actual connection in case
%% of actual configuration
%%
%% @spec handle_connection(ConfigurationLine, State, IsExisting) -> ok
%% @end
%%--------------------------------------------------------------------

%% new config defines that connection shoulbe up, and we did not found
%% it in actual pool
handle_connection(ConfLine, up, false) ->
    {UName, Host, Port, Login, Password, _State} = ConfLine,
    ?SYS_DEBUG("Found new configuration for SMSC connection (~p)", [UName]),
    start_connection(Host, Port, Login, Password, UName),
    ok;

%% new config defines that connection shoulbe up, and we found it
%% in actual pool
handle_connection(ConfLine, up, true) ->
    %% check if actual config is the same, if not, kill connection
    %% and set the new one
    {UName, Host, Port, Login, Password, _State} = ConfLine,
    case catch(gen_server:call(UName, get_actual_config)) of
        {OldUName, OldHost, OldPort, OldLogin, OldPassword} ->
            case {Host, Port, Login, Password} =:= {OldHost, OldPort, OldLogin, OldPassword} of
                false ->
                    ?SYS_DEBUG("Configuration for SMSC connection (~p) has changed - restarting connection", [OldUName]),
                    gen_server:call(OldUName, stop),
                    start_connection(Host, Port, Login, Password, UName);
                true ->
                    ?SYS_DEBUG("Configuration for connection (~p) is unchanged", [OldUName])
            end;
        _Error ->
            ?SYS_DEBUG("Configuration for connection (~p) is unreachable, ignoring", [UName]),
            start_connection(Host, Port, Login, Password, UName)
    end,
    ok;

%% new config defines that connection shoulbe down, and we found it
%% in actual pool
handle_connection(ConfLine, down, true) ->
    {UName, _Host, _Port, _Login, _Password, _State} = ConfLine,
    ?SYS_DEBUG("SMSC connection (~s) state has changed in configuration - closing connection", [UName]),
    gen_server:call(UName, terminate);

%% new config defines that connection shoulbe down, and we did not
%% found it in actual pool
handle_connection(_ConfLine, down, false) ->
    %% so we are doin nothing
    ok.

