-module(ucp_conn).
-author('andrzej.trawinski@jtendo.com').
-author('adam.rutkowski@jtendo.com').

-behaviour(gen_fsm2).

%%----------------------------------------------------------------------
%% UCP SMSC client state machine.
%% Possible states are:
%%     connecting - actually disconnected, but retrying periodically
%%     wait_auth_response  - connected and sent auth message
%%     active - bound to SMSC server and ready to handle commands
%%     wait_reply - sent command and waiting for reply
%%----------------------------------------------------------------------

-include_lib("ucp_common/include/ucp_syntax.hrl").
-include("logger.hrl").
-include("utils.hrl").

%% API
-export([start_link/1,
         get_reverse_config/1,
         get_name/1,
         send_message/3,
         send_message/4,
         close/1]).

%% gen_fsm callbacks
-export([init/1,
         connecting/2,
         connecting/3,
         wait_auth_response/3,
         wait_response/3,
         active/3,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).

%% gen_fsm2 callback
-export([handle_state/2]).

-define(SERVER, ?MODULE).
-define(CMD_TIMEOUT, ?CFG(cmd_timeout, ucp_conf, 3000)).
-define(SEND_TIMEOUT, ?CFG(send_timeout, ucp_conf, 1000)).
-define(RETRY_TIMEOUT, ?CFG(retry_timeout, ucp_conf, 10000)).
-define(CALL_TIMEOUT, ?CFG(call_timeout, ucp_conf, 3000)).
-define(CONNECTION_TIMEOUT, ?CFG(connection_timeout, ucp_conf, 2000)).
%% Grace period after auth errors
-define(GRACEFUL_RETRY_TIMEOUT, ?CFG(graceful_retry_timeout, ucp_conf, 5000)).
-define(SENDING_WINDOW_SIZE, ?CFG(sending_window_size, ucp_conf, 1)).
-define(TCP_OPTIONS, [binary, {packet, 0}, {active, true}, {reuseaddr, true},
        {keepalive, true}, {send_timeout, ?SEND_TIMEOUT}, {send_timeout_close, false}]).

-record(state, {
          name,                  %% name of connection
          host,                  %% smsc address
          port,                  %% smsc port
          login,                 %% smsc login
          pass,                  %% smsc password
          socket,                %% smsc socket
          trn,                   %% message sequence number
          cref,                  %% message concatenation reference number
          keepalive_interval,    %% interval between sending keep-alive messages
          keepalive_timer,       %% keep-alive timer
          default_originator,    %% default sms originator
          dict,                  %% dict holding messages params
          msg_q,                 %% queue for messages
          sending_window_size,   %% max number of messages that can be sent to smsc
                                 %% without waiting for acknowledge
          messages_unconfirmed,  %% number of messages waiting for acknowledge
          transition_callback,   %% function called when fsm changes state
          buffer                 %% TCP socket buffer
         }).

%%===================================================================
%% API
%%===================================================================

start_link({Name, {Host, Port, Login, Password}}) ->
    gen_fsm2:start_link(?MODULE, [Name, {Host, Port, Login, Password}],
        %[{debug, [trace]}]).
        []).

%% --------------------------------------------------------------------
%% Get connection name
%% --------------------------------------------------------------------
get_name(Ref) ->
    gen_fsm:sync_send_all_state_event(Ref, get_name).

%% --------------------------------------------------------------------
%% Get connection data as in configuration file
%% --------------------------------------------------------------------
get_reverse_config(Ref) ->
    gen_fsm:sync_send_all_state_event(Ref, get_reverse_config).

%% --------------------------------------------------------------------
%% Send messages
%% --------------------------------------------------------------------
send_message(Ref, Receiver, Message) ->
    send_message(Ref, Receiver, Message, []).

send_message(Ref, Receiver, Message, Opts) ->
    gen_fsm:sync_send_event(Ref, {send_message, {Receiver, Message, Opts}}, ?CALL_TIMEOUT).

%% --------------------------------------------------------------------
%% Shutdown connection (and process) asynchronous.
%% --------------------------------------------------------------------
close(Ref) ->
    gen_fsm:sync_send_all_state_event(Ref, close).

%%===================================================================
%% gen_fsm callbacks
%%===================================================================

init([Name, {Host, Port, Login, Password}]) ->
    confetti:use(ucp_conf, [
            {location, {"ucp_conf.conf", "conf"}},
            {validators, [fun ensure_transition_callback/1]}]),
    SMSConnConfig = confetti:fetch(ucp_conf),
    State = #state{ name = Name,
                    host = Host,
                    port = Port,
                    login = Login,
                    pass = Password,
                    trn = 0,
                    cref = 0,
                    keepalive_interval = proplists:get_value(keepalive_interval,
                        SMSConnConfig, 60000),
                    default_originator = proplists:get_value(default_originator,
                        SMSConnConfig, "orange.pl"),
                    dict = dict:new(),
                    msg_q = queue:new(),
                    transition_callback =
                        proplists:get_value(transition_callback, SMSConnConfig),
                    sending_window_size =
                        proplists:get_value(sending_window_size, SMSConnConfig,
                            ?SENDING_WINDOW_SIZE),
                    messages_unconfirmed = 0},
    % Start connecting after timeout
    ucp_conn_pool:join_pool(self()),
    {ok, connecting, State, 0}.

connecting(timeout, State) ->
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState}.

connecting(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in connecting state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State),
    {next_state, connecting, NewState}.

wait_auth_response(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in wait_auth state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State),
    {next_state, wait_auth_response, NewState}.

wait_response(Event, From, State) ->
    ?SYS_DEBUG("Received event from ~p in wait_response state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State, true),
    {next_state, wait_response, NewState}.

active(Event, From, State) ->
    %?SYS_DEBUG("Received event from ~p in active state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State, true),
    {next_state, active, NewState}.

handle_event(dequeue, StateName, State) ->
    ?SYS_DEBUG("Handling dequeue event in ~p state", [StateName]),
    dequeue_message(State);

handle_event(Event, StateName, State) ->
    ?SYS_INFO("Unhandled event received in state ~p: ~p", [StateName, Event]),
    {next_state, StateName, State}.

handle_sync_event(get_name, _From, StateName, State) ->
    {reply, {name, State#state.name}, StateName, State};

handle_sync_event(get_reverse_config, _From, StateName, State) ->
    ConfLine = {State#state.name, {State#state.host, State#state.port,
                State#state.login, State#state.pass, up}},
    {reply, {conf, ConfLine}, StateName, State};

handle_sync_event(close, _From, _StateName, State) ->
    ?SYS_INFO("Closing connection request", []),
    gen_tcp:close(State#state.socket),
    {stop, normal, ok, State};

handle_sync_event(Event, From, StateName, State) ->
    ?SYS_INFO("Handling sync event from ~p in state ~p: ~p", [From, StateName, Event]),
    {reply, {StateName, State}, StateName, State}.

handle_ucp_packet([], StateName, State) ->
    {next_state, StateName, State};
handle_ucp_packet([RawData|NextData], StateName, State) ->
    ?SYS_DEBUG("Handling packet: ~p", [RawData]),
    {NextStateName, FinalState} = case catch handle_received_data(RawData, State) of
        {ok, NewState} ->
            % process queued messages
            gen_fsm:send_all_state_event(self(), dequeue),
            {get_next_state(NewState), NewState};
        {auth_ok, NewState} ->
            % process queued messages
            gen_fsm:send_all_state_event(self(), dequeue),
            {active, NewState};
        {auth_failed, Reason, NewState} ->
            ?SYS_WARN("Authentication on ~p failed: ~p", [NewState#state.name, Reason]),
            {connecting, close_and_retry(NewState, ?GRACEFUL_RETRY_TIMEOUT)};
        Error ->
            ?SYS_WARN("Error handling TCP data: ~p", [Error]),
            {StateName, State}
    end,
    handle_ucp_packet(NextData, NextStateName, FinalState).

%% --------------------------------------------------------------------
%% Handle packets arriving in various states
%% --------------------------------------------------------------------
handle_info({tcp, _Socket, RawData}, connecting, State) ->
    ?SYS_WARN("TCP packet received when disconnected:~n~p", [RawData]),
    {next_state, connecting, State};

handle_info({tcp, _Socket, RawData}, StateName, State = #state{buffer = B}) ->
    %?SYS_DEBUG("TCP packet received in ~p state: ~p", [StateName, RawData]),
    {Messages, Buffered} = ucp_framing:try_decode(RawData, B),
    %?SYS_INFO("====== Framed: ~p (~p)", [Messages, Buffered]),
    handle_ucp_packet(Messages, StateName, State#state{buffer = Buffered});

handle_info({tcp_closed, _Socket}, StateName, State) ->
    ?SYS_WARN("TCP connection closed in ~p state", [StateName]),
    {next_state, connecting, close_and_retry(State)};

handle_info({tcp_error, _Socket, Reason}, StateName, State) ->
    ?SYS_DEBUG("TCP error occurred in ~p state: ~p", [StateName, Reason]),
    {next_state, connecting, close_and_retry(State)};

%%--------------------------------------------------------------------
%% Handle timers timeouts
%%--------------------------------------------------------------------
handle_info({timeout, Timer, {cmd_timeout, TRN}}, StateName, State) ->
    Dict = State#state.dict,
    NewState = case dict:find(TRN, Dict) of
        {ok, [{Timer, MsgId, _Msg}]} ->
            NewDict = dict:erase(TRN, Dict),
            ?SYS_INFO("Message ~s timed out. TRN: ~p", [MsgId, TRN]),
            State#state{dict = NewDict};
        error ->
            % Timed out message not in dictionary
            ?SYS_WARN("Unknown message timed out. TRN: ~p", [TRN]),
            State
    end,
    case StateName of
        wait_auth_response -> {next_state, connecting, close_and_retry(NewState)};
        _Other -> {next_state, StateName, NewState}
    end;

handle_info({timeout, retry_connect}, connecting, State) ->
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState};

%%--------------------------------------------------------------------
%% Handle keep-alive timer timeout = send keep-alive message to SMSC
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, active, State) ->
    %?SYS_DEBUG("Idle connection. Sending keep-alive message", []),
    Body = ucp_messages:create_cmd_31_body(State#state.login),
    Id = get_message_id("KAM"),
    NQ = queue:in({Id, Body}, State#state.msg_q),
    gen_fsm:send_all_state_event(self(), dequeue),
    {next_state, active, State#state{msg_q = NQ}};

%%--------------------------------------------------------------------
%% Cancel keepalive timer when not in active state
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, StateName, State) ->
    ?SYS_WARN("Canceling keepalive timer in non active state", []),
    cancel_timer(State#state.keepalive_timer),
    {next_state, StateName, State};

%%--------------------------------------------------------------------
%% Handle configuration change
%%--------------------------------------------------------------------
handle_info({config_reloaded, SMSConnConfig}, StateName, State) ->
    ?SYS_INFO("UCP Connection process ~p (~p) received configuration reload notification", [State#state.name, self()]),
    NewState = State#state{
        keepalive_interval = proplists:get_value(keepalive_interval, SMSConnConfig, 60000),
        default_originator = proplists:get_value(default_originator, SMSConnConfig, "orange.pl")
    },
    {next_state, StateName, NewState};

%%--------------------------------------------------------------------
%% Empty process message queue from the rubbish
%%--------------------------------------------------------------------
handle_info(Info, StateName, State) ->
    ?SYS_WARN("Unexpected info (~p) in ~p state: ~p", [Info, StateName, State]),
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

%% check if transition callback is valid {M,F}
ensure_transition_callback(Conf) ->
    case proplists:get_value(transition_callback, Conf) of
        undefined ->
            {ok, Conf};
        {M,F} when is_atom(M), is_atom(F) ->
            {module, M} = code:ensure_loaded(M),
            true = erlang:function_exported(M, F, 2),
            {ok, Conf}
    end.

%% Execute transition callback if defined
apply_transition_callback(Transition, Pid, State) when is_pid(Pid) ->
    case State#state.transition_callback of
        {M,F} -> M:F(Pid, Transition);
        _ -> ok
    end.

%%===================================================================
%% Internal functions
%%===================================================================

%%===================================================================
%% Cut message into pieces (if needed) then put them on the queue
%%===================================================================
enqueue_event(Event, From, State) ->
    enqueue_event(Event, From, State, false).

enqueue_event({send_message, {Receiver, Message, Opts}}, From, State, Notify) ->
    Result = ucp_messages:create_cmd_51_body(
                            State#state.cref,
                            State#state.default_originator,
                            Receiver,
                            Message,
                            Opts),
    case Result of
        {ok, UpdatedCRef, Msgs} ->
            Id = get_message_id(),
            {ok, Q, Ids} = enqueue_message(Msgs, Id, length(Msgs), State#state.msg_q),
            gen_fsm:reply(From, {ok, Ids}),
            case Notify of
                true -> gen_fsm:send_all_state_event(self(), dequeue);
                _ -> ok
            end,
            {ok, State#state{msg_q = Q, cref = UpdatedCRef}};
        _Error ->
            gen_fsm:reply(From, Result),
            {ok, State}
    end;
enqueue_event(Event, From, State, _Notify) ->
    ?SYS_WARN("Unknown event received from ~p: ~p", [From, Event]),
    {ok, State}.

enqueue_message(Msgs, Id, Cnt, Q) ->
    enqueue_message(Msgs, Id, 1, Cnt, Q, []).

enqueue_message([], _Id, _Idx, _Cnt, Q, Ids) ->
    {ok, Q, lists:reverse(Ids)};
enqueue_message([H|T], Id, Idx, Cnt, Q, Ids) ->
    MsgId = lists:concat([Id, "#", Idx, ".", Cnt]),
    ?SYS_DEBUG("Enqueueing message (~s)", [MsgId]),
    %{cmd_body, Cmd, Body} = H,
    NQ = queue:in({MsgId, H}, Q),
    %NQ = queue:in({MsgId, {cmd_body, Cmd, Body#ucp_cmd_5x{ac = hex:to_hexstr(MsgId)}}}, Q),
    enqueue_message(T, Id, Idx+1, Cnt, NQ, [MsgId | Ids]).

%%===================================================================
%% Handle messages from queue
%%===================================================================
dequeue_message(State) ->
    case is_sending_allowed(State) of
        true ->
            %?SYS_DEBUG("Dequeueing...", []),
            case queue:out(State#state.msg_q) of
                {{value, Message}, Q} ->
                    %?SYS_INFO("Canceling keepalive timer", []),
                    cancel_timer(State#state.keepalive_timer),
                    case process_queued_message(Message, State#state{msg_q = Q}) of
                        {_, active, NewState} ->
                            dequeue_message(NewState);
                        Res ->
                            Res
                    end;
                {empty, _} ->
                    Timer = erlang:start_timer(State#state.keepalive_interval, self(), keepalive_timeout),
                    %?SYS_INFO("Starting keepalive timer: ~p", [Timer]),
                    {next_state, active, State#state{keepalive_timer = Timer}}
            end;
       false ->
            %?SYS_DEBUG("Sending not allowed...", []),
            %?SYS_INFO("Canceling keepalive timer", []),
            cancel_timer(State#state.keepalive_timer),
            {next_state, wait_response, State}
    end.

process_queued_message({Id, Body}, State) ->
    case post_message(Id, Body, State) of
        {ok, NewState} ->
            {next_state, get_next_state(NewState), NewState};
        {error, Reason} ->
            ?SYS_DEBUG("Error processing message (~s): ~p", [Id, Reason]),
            % Put it back on the queue and reconnect
            Q = queue:in_r({Id, Body}, State#state.msg_q),
            NewState = close_and_retry(State#state{msg_q = Q}),
            {next_state, connecting, NewState}
    end.

%%===================================================================
%% Connect to SMSC and authenticate
%%===================================================================
connect(State) ->
    ?SYS_DEBUG("Connecting to SMSC: ~p -> ~p:~p", [State#state.name,
                                                   State#state.host,
                                                   State#state.port]),
    case gen_tcp:connect(State#state.host, State#state.port,
            ?TCP_OPTIONS, ?CONNECTION_TIMEOUT) of
        {ok, Socket} ->
            Body = ucp_messages:create_cmd_60_body(State#state.login, State#state.pass),
            Id = get_message_id("AUTH"),
            case post_message(Id, Body, State#state{socket = Socket}) of
                {ok, NewState} ->
                    {ok, wait_auth_response, NewState};
                {error, Reason} ->
                    ?SYS_WARN("Authentication on ~p failed: ~p", [State#state.name, Reason]),
                    {ok, connecting, close_and_retry(State)}
            end;
        {error, Reason} ->
            ?SYS_ERROR("Error connecting to ~p: ~p", [State#state.name, Reason]),
            NewState = close_and_retry(State),
            {ok, connecting, NewState}
    end.

%%===================================================================
%% Close connection and cleanup
%%===================================================================
close_and_retry(State) ->
    close_and_retry(State, ?RETRY_TIMEOUT).

close_and_retry(State, Timeout) ->
    catch gen_tcp:close(State#state.socket),
    % put unconfirmed messages back on queue
    {Queue, UnconfirmedNo} = dict:fold(
              fun(_Id, [{Timer, Id, Msg}|_], {Q, C}) ->
                      cancel_timer(Timer),
                      {queue:in_r({Id, Msg}, Q), C - 1};
                 (_, _, V) ->
                      V
              end, {State#state.msg_q, State#state.messages_unconfirmed}, State#state.dict),
    erlang:send_after(Timeout, self(), {timeout, retry_connect}),
    State#state{socket = null, msg_q = Queue, dict = dict:new(), messages_unconfirmed = UnconfirmedNo}.

%%===================================================================
%% Send message through active socket
%%===================================================================
post_message(MsgId, {cmd_body, CmdId, Body} = Msg, State) ->
    {ok, UpdatedTRN, Message} = ucp_utils:create_message(State#state.trn, CmdId, Body),
    ?SYS_DEBUG("Sending message (~s): ~p", [MsgId, Message]),
    case gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)) of
        ok ->
            NewState = update_sending_counter(1, State),
            Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, UpdatedTRN}),
            %?SYS_INFO("Starting message (~s) timer: ~p", [MsgId, Timer]),
            NewDict = dict:store(UpdatedTRN, [{Timer, MsgId, Msg}], NewState#state.dict),
            {ok, NewState#state{dict = NewDict, trn = UpdatedTRN}};
        Error -> Error
    end.

update_sending_counter(Value, State) ->
    UnconfirmedNo = State#state.messages_unconfirmed + Value,
    State#state{messages_unconfirmed = UnconfirmedNo}.

is_sending_allowed(State) ->
    State#state.messages_unconfirmed < State#state.sending_window_size.

get_next_state(State) ->
    case is_sending_allowed(State) of
        true -> active;
        false -> wait_response
    end.

%%===================================================================
%% Cancel timer
%%===================================================================
cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    %Value = erlang:cancel_timer(Timer),
    %case Value of
        %false -> ok;
        %_ -> ?SYS_DEBUG("Timer ~p canceled with value: ~p", [Timer, Value])
    %end,
    receive
        {timeout, Timer, _} ->
            ok
    after 0 ->
            ok
    end.

%%-----------------------------------------------------------------------
%% Deals with incoming data from socket
%%-----------------------------------------------------------------------
handle_received_data(Data, State) ->
    case ucp_utils:decode_message(Data) of
        {ok, Message} ->
            %?SYS_DEBUG("Processing received message: ~p", [Message]),
            process_message(Message, State);
        Error ->
            % Decoding failed = ignore message
            ?SYS_WARN("Error parsing received data: ~p", [Error]),
            Error
    end.

process_message({#ucp_header{o_r = "R", trn = TRN}, _Body} = Data, State) ->
    % Update counter in state
    NewState = update_sending_counter(-1, State),
    % Cancel timers
    IntTRN = erlang:list_to_integer(TRN),
    case get_msg_rec(IntTRN, NewState#state.dict) of
        {Timer, MsgId, _Msg} ->
            cancel_timer(Timer),
            NewDict = dict:erase(IntTRN, NewState#state.dict),
            process_result(MsgId, Data, NewState#state{dict = NewDict});
        {error, unknown_trn} -> % message must have expired earlier = ignore
            ?SYS_WARN("Unknown TRN: ~s", [TRN]),
            process_result(unknown, Data, NewState)
    end;
process_message({#ucp_header{o_r = "O"} = Header, _Body} = Data, State) ->
    {ok, Ack} = ucp_messages:create_ack(Header),
    %?SYS_DEBUG("Sending ACK message: ~p", [Ack]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Ack)),
    process_operation(Data, State).

%%-----------------------------------------------------------------------
%% Process result message
%%-----------------------------------------------------------------------
process_result(MsgId, {#ucp_header{ot = "31"}, Body}, State) ->
    % just keepalive ack/nack - do nothing
    log_result(MsgId, Body),
    {ok, State};

process_result(MsgId, {#ucp_header{ot = "51"}, Body}, State) ->
    % message reception confirmation
    log_result(MsgId, Body),
    {ok, State};

process_result(MsgId, {#ucp_header{ot = "60"}, Body}, State) ->
    log_result(MsgId, Body),
    case Body of
        #ack{} -> {auth_ok, State};
        #nack{} -> {auth_failed, Body#nack.sm, State}
    end.

log_result(MsgId, Body) ->
    case Body of
        #ack{} -> % confirmed
            ?SYS_DEBUG("Message (~s) acknowledged", [MsgId]);
        #nack{} -> % rejected
            ?SYS_DEBUG("Message (~s) rejected: ~p", [MsgId, Body#nack.sm])
    end.

%%-----------------------------------------------------------------------
%% Process account addressed message
%%-----------------------------------------------------------------------
process_operation({#ucp_header{ot = "52"}, Body}, State) ->
    % Ref message
    Recipient = Body#ucp_cmd_5x.adc,
    Data = Body#ucp_cmd_5x.msg,
    Sender = ucp_utils:decode_sender(Body#ucp_cmd_5x.otoa, Body#ucp_cmd_5x.oadc),
    gen_event:notify(ucp_event, {sms, {Recipient, Sender, Data}}),
    {ok, State};

process_operation({#ucp_header{ot = "53"}, Body}, State) ->
    Info = hex:hexstr_to_list(ucp_utils:from_ira(Body#ucp_cmd_5x.msg)),
    ?SYS_INFO("Received delivery report message: ~p", [Info]),
    {ok, State};

process_operation(Message, State) ->
    ?SYS_DEBUG("Unhandled message: ~p", [Message]),
    {ok, State}.

get_msg_rec(TRN, Dict) ->
    case dict:find(TRN, Dict) of
        {ok, [{Timer, MsgId, Msg}]} ->
            {Timer, MsgId, Msg};
        error ->
            {error, unknown_trn}
    end.

%%-----------------------------------------------------------------------
%% Create message identifier
%%-----------------------------------------------------------------------
get_message_id() ->
    get_message_id("MSG").

get_message_id(Prefix) ->
    lists:concat([Prefix, ".", lists:subtract(erlang:ref_to_list(make_ref()), "#Ref<>")]).
