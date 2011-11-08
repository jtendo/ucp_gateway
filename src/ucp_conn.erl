-module(ucp_conn).
-author('andrzej.trawinski@jtendo.com').
-author('adam.rutkowski@jtendo.com').

-behaviour(gen_fsm2).

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
         %get_status/1,
         get_reverse_config/1,
         get_name/1,
         send_txt_message/3,
         send_bin_message/3,
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

-export([handle_state/2]).

-define(SERVER, ?MODULE).
-define(AUTH_TIMEOUT, 5000).
-define(CMD_TIMEOUT, 3000).
-define(SEND_TIMEOUT, 1000).
-define(RETRY_TIMEOUT, 10000).
-define(CALL_TIMEOUT, 3000).
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
          req_q, %% queue for requests
          transition_callback
         }).

%%%===================================================================
%%% API
%%%===================================================================

start_link({Name, {Host, Port, Login, Password}}) ->
    gen_fsm2:start_link(?MODULE, [Name, {Host, Port, Login, Password}], [{debug,
                [trace, log]}]).

%%% --------------------------------------------------------------------
%%% Get status of connection.
%%% --------------------------------------------------------------------
%get_status(Handle) ->
%    gen_fsm:sync_send_all_state_event(Handle, get_status).

%%% --------------------------------------------------------------------
%%% Get connection name.
%%% --------------------------------------------------------------------
get_name(Handle) ->
    gen_fsm:sync_send_all_state_event(Handle, get_name).

%%% --------------------------------------------------------------------
%%% Get connection data as in configuration file
%%% --------------------------------------------------------------------
get_reverse_config(Handle) ->
    gen_fsm:sync_send_all_state_event(Handle, get_reverse_config).

%%% --------------------------------------------------------------------
%%% Sending messages
%%% --------------------------------------------------------------------
send_txt_message(Handle, Receiver, Message) ->
    gen_fsm:sync_send_event(Handle, {send_txt_message, {Receiver, Message}}, ?CALL_TIMEOUT).

send_bin_message(Handle, Receiver, Message) ->
    gen_fsm:sync_send_event(Handle, {send_bin_message, {Receiver, Message}}, ?CALL_TIMEOUT).

%%% --------------------------------------------------------------------
%%% Shutdown connection (and process) asynchronous.
%%% --------------------------------------------------------------------
close(Handle) ->
    gen_fsm:send_all_state_event(Handle, close).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Name, {Host, Port, Login, Password}]) ->
    confetti:use(ucp_conf, [
            {location, {"ucp_conf.conf", "conf"}},
            {validators, [fun ensure_transition_callback/1]}
        ]),
    SMSConnConfig = confetti:fetch(ucp_conf),
    State = #state{ name = Name,
                    host = Host,
                    port = Port,
                    login = Login,
                    pass = Password,
                    last_usage = erlang:now(), % FIXME
                    trn = 0,
                    reply_timeout = proplists:get_value(smsc_reply_timeout,
                        SMSConnConfig, 20000),
                    keepalive_interval = proplists:get_value(smsc_keepalive_interval,
                        SMSConnConfig, 62000),
                    default_originator = proplists:get_value(smsc_default_originator,
                        SMSConnConfig, "2147"),
                    send_interval = proplists:get_value(smsc_send_interval,
                        SMSConnConfig, "20000"),
                    dict = dict:new(),
                    req_q = queue:new(),
                    transition_callback = proplists:get_value(transition_callback,
                        SMSConnConfig)
                },
    {ok, connecting, State, 0}. % Start connecting after timeout

connecting(timeout, State) ->
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState}.

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

handle_event(close, _StateName, State) ->
    ?SYS_INFO("Closing connection request", []),
    catch gen_tcp:close(State#state.socket),
    {stop, normal, State};

handle_event(Event, StateName, State) ->
    ?SYS_INFO("Unhandled event received in state ~p: ~p", [StateName, Event]),
    {next_state, StateName, State}.

handle_sync_event(get_name, _From, StateName, State) ->
    {reply, {name, State#state.name}, StateName, State};

handle_sync_event(get_reverse_config, _From, StateName, State) ->
    ConfLine = { State#state.name, {State#state.host, State#state.port,
                 State#state.login, State#state.pass, up }},
    {reply, {conf, ConfLine}, StateName, State};

handle_sync_event(Event, From, StateName, State) ->
    ?SYS_INFO("Handling sync event from ~p in state ~p: ~p", [From, StateName, Event]),
    {reply, {StateName, State}, StateName, State}.

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
            % cancel keepalive timer if still alive
            cancel_timer(State#state.keepalive_timer),
            % process queued messages
            {Action, NextState, NewState} = dequeue_messages(State),
            ?SYS_INFO("Starting keepalive timer", []),
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
        {response, Response} ->
            NewState = case Response of
                       {reply, Reply, To, S1} -> gen_fsm:reply(To, Reply),
                           S1;
                       {ok, S1} ->
                           S1
                   end,
            dequeue_messages(NewState);
        Error ->
            ?SYS_WARN("Error handling data: ~p", [Error]),
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
handle_info({timeout, Timer, {cmd_timeout, TRN}}, StateName, State) ->
    ?SYS_DEBUG("Message timed out: ~p", [TRN]),
    case cmd_timeout(Timer, TRN, State) of
        {reply, To, Reason, NewS} -> gen_fsm:reply(To, Reason),
                                     {next_state, StateName, NewS};
        {error, _Reason}           -> {next_state, StateName, State}
    end;

handle_info({timeout, retry_connect}, connecting, State) ->
    ?SYS_WARN("retry_connect timeout!", []),
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState};

%%--------------------------------------------------------------------
%% Handle autorization timeout = retry connection
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, auth_timeout}, wait_auth_response, State) ->
    ?SYS_WARN("auth timeout!", []),
    {next_state, connecting, close_and_retry(State)};

%%--------------------------------------------------------------------
%% Handle keep-alive timer timeout = send keep-alive message to SMSC
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, active, State) ->
    ?SYS_WARN("keepalive timeout!!", []),
    TRN = ucp_utils:get_next_trn(State#state.trn),
    {ok, Message} = ucp_messages:create_cmd_31(TRN, State#state.login),
    ?SYS_INFO("Sending keep-alive message: ~p", [Message]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)),
    Timer = erlang:start_timer(State#state.keepalive_interval, self(), keepalive_timeout),
    {next_state, active, State#state{keepalive_timer = Timer, trn = TRN}};

%%--------------------------------------------------------------------
%% Cancel keepalive timer when not in active state
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, StateName, State) ->
    ?SYS_INFO("Canceling keepalive timer", []),
    cancel_timer(State#state.keepalive_timer),
    {next_state, StateName, State};

%%--------------------------------------------------------------------
%% Handle configuration change
%%--------------------------------------------------------------------
handle_info({config_reloaded, SMSConnConfig}, StateName, State) ->
    ?SYS_INFO("UCP Connection process ~p (~p) received configuration reload
        notification", [State#state.name, self()]),
    NewState = State#state{
        reply_timeout = proplists:get_value(smsc_reply_timeout, SMSConnConfig, 20000),
        keepalive_interval = proplists:get_value(smsc_keepalive_interval, SMSConnConfig, 62000),
        default_originator = proplists:get_value(smsc_default_originator, SMSConnConfig, "2147"),
        send_interval = proplists:get_value(smsc_send_interval, SMSConnConfig, "20000")
    },
    {next_state, StateName, NewState};

%%--------------------------------------------------------------------
%% Empty process message queue from the rubbish
%%--------------------------------------------------------------------
handle_info(Info, StateName, State) ->
    ?SYS_WARN("Unexpected Info: ~p~nIn state: ~p~n when StateData is: ~p", [Info, StateName, State]),
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

%%--------------------------------------------------------------------
%% Handle state 'on entry' - provided by gen_fsm2
%%--------------------------------------------------------------------
handle_state(StateName, State) ->
    apply_transition_callback(StateName, self(), State),
    ignore.

%%%===================================================================
%%% Internal functions - transition reporting
%%%===================================================================

ensure_transition_callback(Conf) ->
    case proplists:get_value(transition_callback, Conf) of
        undefined ->
            {ok, Conf};
        {M,F} when is_atom(M), is_atom(F) ->
            {module, M} = code:ensure_loaded(M),
            true = erlang:function_exported(M, F, 2),
            {ok, Conf}
    end.

apply_transition_callback(Transition, Pid, State) when is_pid(Pid) ->
    case State#state.transition_callback of
        {M,F} -> M:F(Pid, Transition);
        _ -> ok
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
dequeue_messages(State) ->
    ?SYS_DEBUG("Dequeing messages...", []),
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
    ?SYS_INFO("Processing message: ~p", [Event]),
    case process_event(Event, From, State) of
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

% {ok, newstate} lub {error, message}
process_event(Event, From, State) ->
    {ok, Messages, NewState} = generate_messages(Event, State),
    send_messages(Event, From, Messages, NewState).

send_messages(_Event, _From, [], State) ->
    % nothing to send or end of messages
    {ok, State};
send_messages(Event, From, [{TRN, Message}|Rest], State) ->
    ?SYS_DEBUG("Sending message: ~p", [Message]),
    case gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)) of
        ok ->
            Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, TRN}),
            NewDict = dict:store(TRN, [{Timer, Event, From}], State#state.dict),
            send_messages(Event, From, Rest, State#state{dict = NewDict});
        Error -> Error
    end.

generate_messages({send_txt_message, {Receiver, Message}}, State) ->
    TRN = ucp_utils:get_next_trn(State#state.trn),
    {ok, Msg} = ucp_messages:create_cmd_51_text(TRN, State#state.default_originator, Receiver, Message),
    {ok, [{TRN, Msg}], State#state{trn = TRN}};

generate_messages({send_bin_message, {Receiver, Message}}, State) ->
    %TODO: change this!!! Function in ucp_smspp not implmented
    Tpdus = ucp_smspp:create_tpud_message(Message),
    create_bin_message(Receiver, Tpdus, State).

% Process binary parts
create_bin_message(Receiver, Bins, State) ->
    create_bin_message(Receiver, Bins, State, []).

create_bin_message(_Receiver, [], State, Result) ->
    {lists:reverse(Result), State};
create_bin_message(Receiver, [Bin|Tail], State, Result) ->
    TRN = ucp_utils:get_next_trn(State#state.trn),
    {ok, Msg} = ucp_messages:create_cmd_51_binary(TRN, State#state.default_originator,
            Receiver, Bin),
    create_bin_message(Receiver, Tail, State#state{trn = TRN}, [{TRN, Msg}|Result]).


cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    Value = erlang:cancel_timer(Timer),
    ?SYS_DEBUG("Timer ~p canceled with value: ~p", [Timer, Value]),
    receive
        {timeout, Timer, _} ->
            ok
    after 0 ->
            ok
    end.

close_and_retry(State, Timeout) ->
    catch gen_tcp:close(State#state.socket),
    Queue = dict:fold(
              fun(_Id, [{Timer, Event, From}|_], Q) ->
                      cancel_timer(Timer),
                      queue:in_r({Event, From}, Q);
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
            ?SYS_DEBUG("Processing message: ~p", [Message]),
            % TODO: catch processing errors
            {response, process_message(Message, State)};
        Error ->
            % Decoding failed = ignore message
            %TODO: Make sure is't OK?
            ?SYS_WARN("Error parsing data: ~p", [Error]),
            Error
    end.

process_message({#ucp_header{ot = "31", o_r = "R"}, _Body}, State) ->
    % just keepalive ack/nack - do nothing
    {ok, State};

process_message({#ucp_header{ot = "51", o_r = "R", trn = TRN}, Body}, State) ->
    IntTRN = erlang:list_to_integer(TRN),
    {Timer, _Event, From} = get_msg_rec(IntTRN, State#state.dict),
    NewDict = dict:erase(IntTRN, State#state.dict),
    cancel_timer(Timer),
    Reply = check_result(Body),
    {reply, Reply, From, State#state{dict = NewDict}};

process_message({Header = #ucp_header{ot = "52", o_r = "O"}, Body}, State) ->
    % respond with ACK
    ?SYS_INFO("Received message: ~p", [Body]),
    {ok, Message} = ucp_messages:create_ack(Header),
    ?SYS_INFO("Sending ACK message: ~p", [Message]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)),
    %TODO: Check sending result = Don't know what to do when error!!
    {ok, State};

process_message(Message, State) ->
    ?SYS_DEBUG("Unhandled message: ~p", [Message]),
    {ok, State}.

check_result(Result) when is_record(Result, ack) ->
    ok;
check_result(Result) when is_record(Result, nack) ->
    {error, Result#nack.sm}.

%%-----------------------------------------------------------------------
%% Sort out timed out commands
%%-----------------------------------------------------------------------
cmd_timeout(Timer, TRN, State) ->
    Dict = State#state.dict,
    case dict:find(TRN, Dict) of
        {ok, [{Timer, _Event, From}|_Res]} ->
            NewDict = dict:erase(TRN, Dict),
            {reply, From, {error, timeout}, State#state{dict = NewDict}};
        error ->
            {error, timed_out_cmd_not_in_dict}
    end.

get_msg_rec(TRN, Dict) ->
    case dict:find(TRN, Dict) of
        {ok, [{Timer, Event, From}]} ->
            {Timer, Event, From};
        error ->
            throw({error, unknown_trn})
    end.
