%%%-------------------------------------------------------------------
%%% @author Rafał Gałczyński <>
%%% @copyright (C) 2011, Rafał Gałczyński
%%% @doc
%%%
%%% @end
%%% Created : 16 Mar 2011 by Rafał Gałczyński <>
%%%-------------------------------------------------------------------
-module(smsc_connection).

-behaviour(gen_server).
-include("../include/ucp_syntax.hrl").
-include("../include/logger.hrl").
-include("../include/utils.hrl").

%% gen_server callbacks
-export([init/1,
         handle_cast/2,
         handle_call/3,
         handle_info/2,
         terminate/2,
         code_change/3,
         load_config/0,
         start_link/5]).

-define(SERVER, ?MODULE).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]).
-define(CONNECTION_TIMEOUT, 2000).

-record(state, {
          socket,   %% smsc socket
          addr,     %% smsc address
          port,     %% smsc port
          login,    %% smsc login
          pass,     %% smsc password
          state,    %% smsc socket state
          last_usage, %% timestamp of last socket usage
          unique_name, %% unique name of connection
          ucp_ipport, %% unique name of connection
          seq,         %% last used seq
          reply_timeout, %% reply time of smsc
          keepalive_time, %% time distance between sending keepalive ucpM31
          reconnect_time, %% time distance between reconnections
          send_interval, %% time distance between sends
          default_originator %% default sms originator
         }).


%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link(Host, Port, Login, Password, UName) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Host, Port, Login, Password, UName) ->
    gen_server:start_link({local, UName},
                          ?MODULE, [Host, Port, Login, Password, UName], []).

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
init([Address, Port, Login, Password, UName]) ->
    case load_config() of
        {ok, SMSConnConfig} ->
            %% process_flag(trap_exit, true),
            UcpIP = lists:foldr(
                      fun(X, Acc) ->
                              [ucp_utils:fill_with_zeros(X,3)|Acc]
                      end,
                      [],
                      string:tokens(Address,".")),
            State = #state{ addr=Address, port=Port, pass=Password,
                            login=Login, state=disconnected,
                            last_usage=erlang:now(), unique_name = UName,
                            ucp_ipport = lists:flatten(UcpIP) ++ integer_to_list(Port),
                            seq = "00",
                            reply_timeout = proplists:get_value(smsc_reply_timeout, SMSConnConfig, 20000),
                            keepalive_time = proplists:get_value(smsc_keepalive_time, SMSConnConfig, 62000),
                            reconnect_time = proplists:get_value(smsc_reconnect_time, SMSConnConfig, 20000),
                            default_originator = proplists:get_value(smsc_default_originator, SMSConnConfig, "2147"),
                            send_interval = proplists:get_value(smsc_send_interval, SMSConnConfig, "20000")
                          },
            case smsc_connect(State) of
                {ok, NState, _} ->
                    spawn_link(fun() -> keepalive(NState) end),
                    {ok, NState};
                {error, _NState, Reason} ->
                    ?SYS_ERROR("Error connecting to smsc ~p, ~p",
                               [State#state.unique_name, Reason]),
                    {stop, normal}
            end;
        {error, smsc_connection_conf_corrupted} ->
            ?SYS_DEBUG("~p", ["Error in smsc_conn.conf, ignoring of starting connection"]),
            ignore
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

handle_call({send_message,{Receiver, Msg, ReqId}}, _From, State) ->
    Seq = ucp_utils:get_next_seq(State#state.seq),
    Sender = State#state.default_originator,
    {ok, UcpMessage} = ucp_messages:create_m51(Seq, Sender, Receiver, Msg),
    {Reply, NState, _Reason} = send_message(State, UcpMessage, ReqId),
    {reply, Reply, NState#state{seq=Seq}};

handle_call({send_binary_message,{Receiver, Msg, ReqId}}, _From, State) ->
    Seq = ucp_utils:get_next_seq(State#state.seq),
    Sender = State#state.default_originator,
    Messages = ucp_messages:create_m51(Seq, Sender, Receiver, Msg),
    lists:map(fun({ok, Message}) ->
                      binpp:pprint(Message),
                      send_message(State, Message, ReqId)
              end, Messages),
    {reply, ok, State#state{seq=erlang:list_to_integer(Seq) + length(Messages)}};

handle_call(terminate, _From, State) ->
    ?SYS_DEBUG("SMSC ~p received terminate call, disabled in configuration", [State#state.unique_name]),
    {stop, normal , State};

handle_call(get_name, _From, State) ->
    Reply = State#state.unique_name,
    {reply, Reply , State};

handle_call(stop, _From, State)->

    {stop, normal, stopped, State};

handle_call(get_actual_config, _From, State) ->
    Uname = State#state.unique_name,
    Host = State#state.addr,
    Port = State#state.port,
    Login = State#state.login,
    Pass = State#state.pass,
    Reply = {Uname, Host, Port, Login, Pass},
    {reply, Reply , State};

handle_call({state_update,NewState}, _From, _State) ->
    {reply, ok , NewState};

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
    ?SYS_DEBUG("~p terminating",[self()]),
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

update_state(NewState) ->
    ?SYS_DEBUG("Updating state to:~n~p", [NewState]),
    gen_server:call(
      NewState#state.unique_name,
      {state_update, NewState}).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% KeepAlive function, should by spawned
%%
%% @spec keepalive(State) -> exit() | keepalive(State)
%% @end
%%--------------------------------------------------------------------

keepalive(State) ->
    receive
    after State#state.keepalive_time ->
            Seq = ucp_utils:get_next_seq(State#state.seq),
            {ok, UcpMessage} =
                ucp_messages:create_m31(Seq, State#state.login),
            case send_message(State, UcpMessage, keepalive) of
                {ok, NState, _ErrMsg} ->
                    keepalive(NState#state{seq = Seq});
                {error, NState, ErrMsg} ->
                    ?SYS_ERROR("SMSC keepalive problem (~s), reconnecting", [ErrMsg]),
                    {ok, RState} = smsc_reconnect(NState),
                    update_state(RState),
                    keepalive(RState)
            end
    end.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to reconnect to smsc
%%
%% @spec smsc_reconnect(State) -> {ok, State}
%% @end
%%--------------------------------------------------------------------

smsc_reconnect(State) ->
    case State#state.socket of
        undefined ->
            ?SYS_DEBUG("~p",["Socket undefined, not closing"]);
        Socket ->
            ok = gen_tcp:close(Socket)
    end,
    case smsc_connect(State) of
        {ok, NState, _Reason} ->
            ?SYS_DEBUG("~p",["SMSC Reconnection OK"]),
            {ok, NState};
        {error, NState, ErrorReason} ->
            ?SYS_ERROR("SMSC Reconnection ~p, sleep and reconnect", [ErrorReason]),
            sleep(State#state.reconnect_time),
            smsc_reconnect(NState)
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to connect and login  to smsc
%%
%% @spec smsc_connect(State) -> {ok, State, ErrMsg} | {error, State, ErrMsg}
%% @end
%%--------------------------------------------------------------------

smsc_connect(State) ->
    ?SYS_DEBUG("Connecting to ~p : ~p", [State#state.addr, State#state.port]),
    case gen_tcp:connect(
           State#state.addr,
           State#state.port,
           ?TCP_OPTIONS, ?CONNECTION_TIMEOUT) of
        {ok, Socket} ->
            ?SYS_DEBUG("Connected to ~p : ~p", [State#state.addr, State#state.port]),
            NewState = State#state{socket=Socket, state=connected},
            ?SYS_DEBUG("Sending login/pass (~p/~p) to ~p : ~p", [NewState#state.login, NewState#state.pass, State#state.addr, State#state.port]),
            smsc_login(
              NewState#state.login,
              NewState#state.pass,
              NewState);
        {error,Reason} ->
            ?SYS_DEBUG("Error connecting to ~p : ~p => ~p", [State#state.addr, State#state.port, Reason]),
            NewState = State#state{state=Reason, socket=undefined},
            {error, NewState, Reason}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function try to login to smsc
%%
%% @spec smsc_login(Login, Password, State) -> {ok, State, ErrMsg} | {error, State, ErrMsg}
%% @end
%%--------------------------------------------------------------------

smsc_login(Login, Password, State) ->
    Seq = ucp_utils:get_next_seq(State#state.seq),
    {ok, UcpMessage} = ucp_messages:create_m60(Seq, Login,Password),
    case send_message(State#state{seq = Seq}, UcpMessage, login) of
        {ok, NState, ok} ->
            {ok, NState, ok};
        {error, NState, Error} ->
            {error, NState, Error}
    end.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for sending UCP messages via smsc connection
%%
%% @spec send_message(State, UCPMessage, ReqId) -> {ok, State, ok} | {error, State, ErrorMsg}
%% @end
%%--------------------------------------------------------------------

send_message(State, UcpMessage, ReqId) ->
    Socket = State#state.socket,
    UName = State#state.unique_name,
    UsageTimeDiff = timer:now_diff(erlang:now(), State#state.last_usage),
    AllowedTimeDiff = State#state.send_interval,

    case UsageTimeDiff < AllowedTimeDiff of
        true ->
            ?SYS_DEBUG("~s| SMSC connection send interval to small [~s µs], slepping for [~s µs]",
                       [ReqId, integer_to_list(UsageTimeDiff), integer_to_list(AllowedTimeDiff-UsageTimeDiff)]),
            ?SYS_DEBUG("~s| SMSC sleeping for ~s µs" , [ReqId, integer_to_list(AllowedTimeDiff-UsageTimeDiff)]),
            sleep(AllowedTimeDiff - UsageTimeDiff);
        false ->
            ok
    end,
    case Socket of
        undefined ->
            ?SYS_ERROR("~p",["SMSC socket error"]),
            {error, State, socket_undefined};
        _ ->
            case gen_tcp:send(Socket, UcpMessage) of
                ok ->
                    case gen_tcp:recv(Socket, 0, State#state.reply_timeout) of
                        {ok, Data} ->
                            UcpMessages = binary:split(Data,[<<3>>],[global]),
                            AnalyzeOutput = analyze_ucp_message(UcpMessages, UName),
                            case lists:member(ack, AnalyzeOutput) of
                                true ->
                                    {ok, State, ok};
                                false ->
                                    {error, State, "Not received ACK"}
                            end;
                        {error, Reason} ->
                            ?SYS_ERROR("~s| No SMSC (~p) response : ~p", [ReqId, UName, Reason]),
                            NewState = State#state{last_usage = erlang:now()},
                            {error, NewState, Reason}
                    end;
                {error, Reason} ->
                    ?SYS_ERROR("Error sending msg (~p) to SMSC (~p): ~p", [ReqId, UName, Reason]),
                    {error, State, Reason}
            end
    end.

analyze_ucp_message([], _UName) ->
    [ok];

analyze_ucp_message([<<>>|RestofMessages], UName) ->
    analyze_ucp_message(RestofMessages, UName);

analyze_ucp_message([UcpMessage|RestofMessages], UName) ->
    {_Header, Body} = ucp_utils:unpackUCP(UcpMessage),
    {Type, Error} = ucp_utils:analyze_ucp_body(Body),
    case Type  of
        ack ->
            ?SYS_DEBUG("SMSC (~p) response : ack",
                       [UName]);
        nack ->
            ?SYS_DEBUG("SMSC (~p) response : ~p (~p)",
                       [UName, Type, Error]);
        ucp5x ->
            ?SYS_DEBUG("SMSC (~p) msg ucp52 received - ignoring: ~p",
                       [UName, Type])
    end,
    [Type | analyze_ucp_message(RestofMessages, UName)].



sleep(T) ->
    receive
    after
        T -> true
    end.


load_config(Filename) ->
    case file:consult(?PRIV(Filename)) of
        {ok, SMSCConf} ->
            {ok, SMSCConf};
        {error, _Reason} ->
            ?SYS_FATAL("Invalid ~s", [Filename]),
            {error, smsc_connection_conf_corrupted}
    end.

load_config() ->
    case load_config("smsc_conn.conf") of
        {ok, SMSConfig} ->
            {ok, SMSConfig};
        {error, smsc_connection_conf_corrupted} ->
            {error, smsc_connection_conf_corrupted}
    end.
