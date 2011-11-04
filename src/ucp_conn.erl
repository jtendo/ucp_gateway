%%%-------------------------------------------------------------------
%%% @author Andrzej Trawinski
%%% @copyright (C) 2011, jtendo/
%%% @doc
%%%
%%% @end
%%% Created : 2011-10-27 09:51:40.456108
%%%-------------------------------------------------------------------
-module(ucp_conn).

-behaviour(gen_fsm).

%%%----------------------------------------------------------------------
%%% UCP SMSC client state machine.
%%% Possible states are:
%%%     connecting - actually disconnected, but retrying periodically
%%%     wait_auth_response  - connected and sent auth request
%%%     active - bound to SMSC server and ready to handle commands
%%%----------------------------------------------------------------------

-include("ucp_syntax.hrl").
-include("logger.hrl").
-include("utils.hrl").

%% API
-export([start_link/1,
         get_status/1,
         close/1]).

%% gen_fsm callbacks
-export([init/1,
         connecting/2,
         connecting/3,
         wait_auth_response/3,
         active/3,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).

-define(SERVER, ?MODULE).
-define(AUTH_TIMEOUT, 5000).
-define(CMD_TIMEOUT, 2000).
-define(SEND_TIMEOUT, 1000).
-define(RETRY_TIMEOUT, 10000).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, true}, {reuseaddr, true},
        {keepalive, true}, {send_timeout, ?SEND_TIMEOUT}, {send_timeout_close, false}]).
-define(CONNECTION_TIMEOUT, 2000).
%% Grace period after auth errors:
-define(GRACEFUL_RETRY_TIMEOUT, 5000).
-define(MIN_MESSAGE_TRN, 0).
-define(MAX_MESSAGE_TRN, 99).

-record(state, {
          name,     %% Name of connection
          host,     %% smsc address
          port,     %% smsc port
          login,    %% smsc login
          pass,     %% smsc password
          socket,   %% smsc socket
          auth_timer, %% ref to auth timeout
          last_usage, %% timestamp of last socket usage
          trn = 0,   %% message sequence number
          reply_timeout, %% reply time of smsc
          keepalive_interval, %% interval between sending keepalive ucp31 messages
          keepalive_timer,
          send_interval, %% time distance between sends
          default_originator, %% default sms originator
          dict, %% dict holding operation params and results
          req_q %% queue for requests
         }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link(Host, Port, Login, Password, UName) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link({Name, Host, Port, Login, Password}) ->
    gen_fsm:start_link(?MODULE, [Name, Host, Port, Login, Password], [{debug,
                [trace, log]}]).

%%% --------------------------------------------------------------------
%%% Get status of connection.
%%% --------------------------------------------------------------------
get_status(Handle) ->
    gen_fsm:sync_send_all_state_event(Handle, get_status).

%%% --------------------------------------------------------------------
%%% Shutdown connection (and process) asynchronous.
%%% --------------------------------------------------------------------
close(Handle) ->
    gen_fsm:send_all_state_event(Handle, close).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init([Name, Host, Port, Login, Password]) ->
    confetti:use(ucp_conf),
    SMSConnConfig = confetti:fetch(ucp_conf),
    State = #state{ name = Name,
                    host = Host,
                    port = Port,
                    login = Login,
                    pass = Password,
                    last_usage = erlang:now(),
                    trn = 0,
                    reply_timeout = proplists:get_value(smsc_reply_timeout, SMSConnConfig, 20000),
                    keepalive_interval = proplists:get_value(smsc_keepalive_interval, SMSConnConfig, 62000),
                    default_originator = proplists:get_value(smsc_default_originator, SMSConnConfig, "2147"),
                    send_interval = proplists:get_value(smsc_send_interval, SMSConnConfig, "20000"),
                    dict = dict:new(),
                    req_q = queue:new()},
    {ok, connecting, State, 0}. % Start connecting after timeout

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
connecting(timeout, State) ->
    lager:info("Timeout 0!"),
    ucp_conn_pool:join_pool(),
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
connecting(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in connecting state: ~p", [From, Event]),
    Q = queue:in({Event, From}, State#state.req_q),
    {next_state, connecting, State#state{req_q = Q}}.

wait_auth_response(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in wait_auth state: ~p", [From, Event]),
    Q = queue:in({Event, From}, State#state.req_q),
    {next_state, wait_auth_response, State#state{req_q = Q}}.

active(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in active state: ~p", [From, Event]),
    process_message(Event, From, State).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event(close, _StateName, State) ->
    ?SYS_INFO("Closing connection request", []),
    catch gen_tcp:close(State#state.socket),
    {stop, normal, State};

handle_event(Event, StateName, State) ->
    ?SYS_INFO("Unhandled event received in state ~p: ~p", [StateName, Event]),
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(Event, From, StateName, State) ->
    ?SYS_INFO("Handling sync event from ~p in state ~p: ~p", [From, StateName, Event]),
    {reply, {StateName, State}, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------

%%
%% Packets arriving in various states
%%
handle_info({tcp, _Socket, RawData}, connecting, State) ->
    ?SYS_WARN("TCP packet received when disconnected:~n~p", [RawData]),
    {next_state, connecting, State};

handle_info({tcp, _Socket, RawData}, wait_auth_response, State) ->
    ?SYS_DEBUG("TCP packet received when wait_auth_response:~n~p", [RawData]),
    cancel_timer(State#state.auth_timer),
    case catch received_wait_auth_response(RawData, State) of
        ok ->
            {Action, NextState, NewState} = dequeue_messages(State),
            lager:info("Starting keepalive timer"),
            Timer = erlang:start_timer(NewState#state.keepalive_interval, self(), keepalive_timeout),
            {Action, NextState, NewState#state{keepalive_timer = Timer}};
        {auth_failed, Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State, ?GRACEFUL_RETRY_TIMEOUT)};
        {'EXIT', Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State)};
        {error, Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State)}
    end;

handle_info({tcp, _Socket, Data}, active, State) ->
    case catch received_active(Data, State) of
        {response, Response, _RequestType} ->
            NewState = case Response of
                       {reply, Reply, To, S1} -> gen_fsm:reply(To, Reply),
                           S1;
                       {ok, S1} ->
                           S1
                   end,
            dequeue_messages(NewState);
        _ ->
            {next_state, active, State}
    end;

handle_info({tcp_closed, _Socket}, StateName, State) ->
    ?SYS_WARN("SMSC server closed the connection: ~p~nIn State: ~p",
                 [State#state.name, StateName]),
    {next_state, connecting, close_and_retry(State)};

handle_info({tcp_error, _Socket, Reason}, StateName, State) ->
    ?SYS_DEBUG("TCP error received: ~p~nIn State: ~p", [Reason, StateName]),
    {next_state, connecting, close_and_retry(State)};

%%--------------------------------------------------------------------
%% Handling timers timeouts
%%--------------------------------------------------------------------
handle_info({timeout, Timer, {cmd_timeout, Id}}, StateName, S) ->
    lager:info("Timeout 1"),
    case cmd_timeout(Timer, Id, S) of
        {reply, To, Reason, NewS} -> gen_fsm:reply(To, Reason),
                                     {next_state, StateName, NewS};
        {error, _Reason}           -> {next_state, StateName, S}
    end;

handle_info({timeout, retry_connect}, connecting, State) ->
    lager:info("retry_connect timeout!"),
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState};

%%--------------------------------------------------------------------
%% Handle autorization timeout = retry connection
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, auth_timeout}, wait_auth_response, State) ->
    lager:info("auth timeout!"),
    {next_state, connecting, close_and_retry(State)};

%%--------------------------------------------------------------------
%% Handle keep-alive timer timeout = send keep-alive message to SMSC
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, active, State) ->
    lager:info("keepalive timeout!!"),
    TRN = ucp_utils:get_next_trn(State#state.trn),
    {ok, Message} = ucp_messages:create_cmd_31(TRN, State#state.login),
    lager:info("Sending keep-alive message: ~p", [Message]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)),
    Timer = erlang:start_timer(State#state.keepalive_interval, self(), keepalive_timeout),
    {next_state, active, State#state{keepalive_timer = Timer, trn = TRN}};

%%--------------------------------------------------------------------
%% Cancel keepalive timer when not in active state
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, StateName, State) ->
    lager:info("Canceling keepalive timer"),
    cancel_timer(State#state.keepalive_timer),
    {next_state, StateName, State};

%%--------------------------------------------------------------------
%% Empty process message queue from the rubbish
%%--------------------------------------------------------------------
handle_info(Info, StateName, State) ->
    lager:info("Unexpected Info: ~p~nIn state: ~p~n when StateData is: ~p", [Info, StateName, State]),
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->
    ?SYS_DEBUG("~p terminating", [self()]),
    ok.

%%--------------------------------------------------------------------
%% Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
        {ok, StateName, State}.


%%%===================================================================
%%% Internal functions
%%%===================================================================
dequeue_messages(State) ->
    lager:info("Dequeing messages..."),
    case queue:out(State#state.req_q) of
        {{value, {Event, From}}, Q} ->
            case process_message(Event, From, State#state{req_q=Q}) of
                {_, active, NewState} ->
                    dequeue_messages(NewState);
                Res ->
                    Res
            end;
        {empty, _} ->
            {next_state, active, State}
    end.

process_message(Event, From, State) ->
    lager:info("Processing message: ~p", [Event]),
    case send_message(Event, From, State) of
        {ok, NewState} ->
            {next_state, active, NewState};
        {error, _Reason} ->
            Q = queue:in_r({Event, From}, State#state.req_q),
            NewState = close_and_retry(State#state{req_q = Q}),
            {next_state, connecting, NewState}
    end.

connect(State) ->
    ?SYS_DEBUG("Connecting to ~p -> ~p:~p", [State#state.name, State#state.host, State#state.port]),
    case gen_tcp:connect(State#state.host, State#state.port, ?TCP_OPTIONS, ?CONNECTION_TIMEOUT) of
        {ok, Socket} ->
            case send_auth_message(State#state{socket = Socket}) of
                {ok, NewState} ->
                    Timer = erlang:start_timer(?AUTH_TIMEOUT, self(), auth_timeout),
                    {ok, wait_auth_response, NewState#state{auth_timer = Timer}};
                {error, Reason} ->
                    report_auth_failure(State, Reason),
                    {ok, connecting, close_and_retry(State)}
            end;
        {error, Reason} ->
            ?SYS_ERROR("SMSC connection ~p failed: ~p", [State#state.name, Reason]),
            NewState = close_and_retry(State),
            {ok, connecting, NewState}
    end.

report_auth_failure(State, Reason) ->
    ?SYS_WARN("SMSC authentication failed on ~s: ~p", [State#state.name, Reason]).

send_auth_message(State) ->
    TRN = ucp_utils:get_next_trn(State#state.trn),
    {ok, Message} = ucp_messages:create_cmd_60(TRN, State#state.login, State#state.pass),
    ?SYS_DEBUG("Sending auth message: ~p", [Message]),
    case gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)) of
        ok -> {ok, State#state{trn = TRN}};
        Error -> Error
    end.

send_message(Event = {_Type, Message}, From, State) ->
    %UsageTimeDiff = timer:now_diff(erlang:now(), State#state.last_usage),
    %AllowedTimeDiff = State#state.send_interval,
    %case UsageTimeDiff < AllowedTimeDiff of
        %true ->
            %?SYS_DEBUG("~s| SMSC connection send interval to small [~s µs], slepping for [~s µs]",
                       %[ReqId, integer_to_list(UsageTimeDiff), integer_to_list(AllowedTimeDiff-UsageTimeDiff)]),
            %?SYS_DEBUG("~s| SMSC sleeping for ~s µs" , [ReqId, integer_to_list(AllowedTimeDiff-UsageTimeDiff)]),
            %sleep(AllowedTimeDiff - UsageTimeDiff);
        %false ->
            %ok
    %end,
    ?SYS_DEBUG("Sending message: ~p", [Message]),
    case gen_tcp:send(State#state.socket, Message) of
        ok ->
            Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, State#state.trn}),
            NewDict = dict:store(State#state.trn, [{Timer, Event, From, "Name"}], State#state.dict),
            %New_dict = dict:store(Id, [{Timer, Command, From, Name}], S#eldap.dict),
            {ok, State#state{dict = NewDict}};
        Error -> Error
    end.

%handle_call({send_message,{Receiver, Msg, ReqId}}, _From, State) ->
    %Seq = ucp_utils:get_next_seq(State#state.seq),
    %Sender = State#state.default_originator,
    %{ok, UcpMessage} = ucp_messages:create_m51(Seq, Sender, Receiver, Msg),
    %{Reply, NState, _Reason} = send_message(State, UcpMessage, ReqId),
    %{reply, Reply, NState#state{seq=Seq}};

%handle_call({send_binary_message,{Receiver, Msg, ReqId}}, _From, State) ->
    %Seq = ucp_utils:get_next_seq(State#state.seq),
    %Sender = State#state.default_originator,
    %Messages = ucp_messages:create_m51(Seq, Sender, Receiver, Msg),
    %lists:map(fun({ok, Message}) ->
                      %binpp:pprint(Message),
                      %send_message(State, Message, ReqId)
              %end, Messages),
    %{reply, ok, State#state{seq=erlang:list_to_integer(Seq) + length(Messages)}};

cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    receive
        {timeout, Timer, _} ->
            ok
    after 0 ->
            ok
    end.

close_and_retry(State, Timeout) ->
    catch gen_tcp:close(State#state.socket),
    Queue = dict:fold(
              fun(_Id, [{Timer, Command, From, _Name}|_], Q) ->
                      cancel_timer(Timer),
                      queue:in_r({Command, From}, Q);
                 (_, _, Q) ->
                      Q
              end, State#state.req_q, State#state.dict),
    erlang:send_after(Timeout, self(), {timeout, retry_connect}),
    State#state{socket = null, req_q = Queue, dict = dict:new()}.

close_and_retry(State) ->
    close_and_retry(State, ?RETRY_TIMEOUT).

%%-----------------------------------------------------------------------
%% received_wait_auth_response packet
%% Deals with incoming packets in the wait_auth_response state
%% Will return one of:
%%  ok - Success - move to active state
%%  {auth_failed, Reason} - Failed
%%  {error, Reason}
%%  {'EXIT', Reason} - Broken packet
%%-----------------------------------------------------------------------
received_wait_auth_response(Data, State) ->
    case ucp_utils:decode_message(Data) of
        {ok, {Header, Body}} ->
             check_trn(list_to_integer(Header#ucp_header.trn), State#state.trn),
             check_auth_result(Body);
        Else ->
             {auth_failed, Else}
    end.

check_auth_result(Result) when is_record(Result, ack) ->
    ok;
check_auth_result(Result) when is_record(Result, nack) ->
    {auth_failed, Result#nack.sm}.

%%--------------------------------------------------------------------
%% Compare TRN values
%%--------------------------------------------------------------------
check_trn(TRN, TRN) -> ok;
check_trn(_, _)   -> throw({error, wrong_auth_trn}).

%%-----------------------------------------------------------------------
%% received_active
%% Deals with incoming messages in the active state
%% Will return one of:
%%  {ok, NewS} - Don't reply to client
%%  {reply, Result, From, NewS} - Reply with result to client From
%%  {error, Reason}
%%  {'EXIT', Reason} - Broke
%%-----------------------------------------------------------------------
received_active(Data, State) ->
    case ucp_utils:decode_message(Data) of
        {ok, Message} ->
            process_message(Message, State);
        _Else ->
            % Decoding failed = ignore message
            %TODO: Make sure is't OK?
            lager:info("Unknown data: ~p", [Data]),
            {ok, State}
    end.

process_message({#ucp_header{ot = "31", o_r = "R"}, _Body}, State) ->
    % just keepalive ack/nack - do nothing
    {ok, State};

process_message({Header = #ucp_header{ot = "52", o_r = "O"}, Body}, State) ->
    % respond with ACK
    lager:info("Received message: ~p", [Body]),
    {ok, Message} = ucp_messages:create_ack(Header),
    lager:info("Sending ACK message: ~p", [Message]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)),
    %TODO: Check sending result = Don't know what to do when error!!
    {ok, State}.

%%-----------------------------------------------------------------------
%% Sort out timed out commands
%%-----------------------------------------------------------------------
cmd_timeout(Timer, Id, State) ->
    Dict = State#state.dict,
    case dict:find(Id, Dict) of
        {ok, [{Timer, _Command, From, _Name}|_Res]} ->
            NewDict = dict:erase(Id, Dict),
            {reply, From, {error, timeout}, State#state{dict = NewDict}};
        error ->
            {error, timed_out_cmd_not_in_dict}
    end.
