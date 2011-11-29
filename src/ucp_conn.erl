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

-export([handle_state/2]).

-define(SERVER, ?MODULE).
-define(CMD_TIMEOUT, ?CFG(cmd_timeout, ucp_conf, 3000)).
-define(SEND_TIMEOUT, ?CFG(send_timeout, ucp_conf, 1000)).
-define(RETRY_TIMEOUT, ?CFG(retry_timeout, ucp_conf, 10000)).
-define(CALL_TIMEOUT, ?CFG(call_timeout, ucp_conf, 6000)).
-define(CONNECTION_TIMEOUT, ?CFG(connection_timeout, ucp_conf, 2000)).
%% Grace period after auth errors:
-define(GRACEFUL_RETRY_TIMEOUT, ?CFG(graceful_retry_timeout, ucp_conf, 5000)).
-define(SENDING_WINDOW_SIZE, ?CFG(sending_window_size, ucp_conf, 1)).

-define(TCP_OPTIONS, [binary, {packet, 0}, {active, true}, {reuseaddr, true},
        {keepalive, true}, {send_timeout, ?SEND_TIMEOUT}, {send_timeout_close, false}]).

-record(state, {
          name,     %% Name of connection
          host,     %% smsc address
          port,     %% smsc port
          login,    %% smsc login
          pass,     %% smsc password
          socket,   %% smsc socket
          trn,   %% message sequence number
          cref, %% message concatenation reference number
          reply_timeout, %% reply time of smsc
          keepalive_interval, %% interval between sending keepalive ucp31 messages
          keepalive_timer,
          default_originator, %% default sms originator
          dict, %% dict holding operation params and results
          req_q, %% queue for requests
          sending_window_size,
          messages_unconfirmed,
          transition_callback
         }).

%%%===================================================================
%%% API
%%%===================================================================

start_link({Name, {Host, Port, Login, Password}}) ->
    gen_fsm2:start_link(?MODULE, [Name, {Host, Port, Login, Password}],
        [{debug, [trace]}]).

%%% --------------------------------------------------------------------
%%% Get connection name.
%%% --------------------------------------------------------------------
get_name(Ref) ->
    gen_fsm:sync_send_all_state_event(Ref, get_name).

%%% --------------------------------------------------------------------
%%% Get connection data as in configuration file
%%% --------------------------------------------------------------------
get_reverse_config(Ref) ->
    gen_fsm:sync_send_all_state_event(Ref, get_reverse_config).

%%% --------------------------------------------------------------------
%%% Sending messages
%%% --------------------------------------------------------------------
send_message(Ref, Receiver, Message) ->
    send_message(Ref, Receiver, Message, []).

send_message(Ref, Receiver, Message, Opts) ->
    gen_fsm:sync_send_event(Ref, {send_message, {Receiver, Message, Opts}}, ?CALL_TIMEOUT).

%%% --------------------------------------------------------------------
%%% Shutdown connection (and process) asynchronous.
%%% --------------------------------------------------------------------
close(Ref) ->
    gen_fsm:send_all_state_event(Ref, close).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

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
                    reply_timeout = proplists:get_value(reply_timeout,
                        SMSConnConfig, 20000),
                    keepalive_interval = proplists:get_value(keepalive_interval,
                        SMSConnConfig, 62000),
                    default_originator = proplists:get_value(default_originator,
                        SMSConnConfig, "orange.pl"),
                    dict = dict:new(),
                    req_q = queue:new(),
                    transition_callback =
                        proplists:get_value(transition_callback, SMSConnConfig),
                    sending_window_size =
                        proplists:get_value(sending_window_size, SMSConnConfig,
                            ?SENDING_WINDOW_SIZE),
                    messages_unconfirmed = 0},
    {ok, connecting, State, 0}. % Start connecting after timeout

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
    ?SYS_INFO("Received event from ~p in wait_response state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State),
    {next_state, wait_response, NewState}.

active(Event, From, State) ->
    ?SYS_INFO("Received event from ~p in active state: ~p", [From, Event]),
    {ok, NewState} = enqueue_event(Event, From, State),
    ?SYS_DEBUG("State: ~p", [NewState]),
    {next_state, active, NewState}.

handle_event(dequeue, StateName, State) ->
    ?SYS_INFO("Handling dequeue event in state: ~p", [StateName]),
    dequeue_message(State);

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
    ConfLine = {State#state.name, {State#state.host, State#state.port,
                State#state.login, State#state.pass, up}},
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

handle_info({tcp, _Socket, RawData}, StateName, State) ->
    ?SYS_DEBUG("TCP packet received in ~p state: ~p", [StateName, RawData]),
    case catch handle_received_data(RawData, State) of
        {ok, NewState} ->
            % process queued messages
            gen_fsm:send_all_state_event(self(), dequeue),
            {next_state, StateName, NewState};
        {auth_ok, NewState} ->
            % process queued messages
            gen_fsm:send_all_state_event(self(), dequeue),
            {next_state, active, NewState};
        {auth_failed, Reason, NewState} ->
            ?SYS_WARN("Authentication on ~p failed: ~p", [NewState#state.name, Reason]),
            {next_state, connecting, close_and_retry(NewState, ?GRACEFUL_RETRY_TIMEOUT)};
        Error ->
            ?SYS_WARN("Error handling TCP data: ~p", [Error]),
            {next_state, StateName, State}
    end;

handle_info({tcp_closed, _Socket}, StateName, State) ->
    ?SYS_WARN("TCP connection closed in ~p state", [StateName]),
    {next_state, connecting, close_and_retry(State)};

handle_info({tcp_error, _Socket, Reason}, StateName, State) ->
    ?SYS_DEBUG("TCP error occurred in ~p state: ~p", [StateName, Reason]),
    {next_state, connecting, close_and_retry(State)};

%%--------------------------------------------------------------------
%% Handling timers timeouts
%%--------------------------------------------------------------------
handle_info({timeout, Timer, {cmd_timeout, TRN}}, StateName, State) ->
    Dict = State#state.dict,
    NewState = case dict:find(TRN, Dict) of
        {ok, [{Timer, MsgId, _Msg}]} ->
            NewDict = dict:erase(TRN, Dict),
            ?SYS_INFO("Message ~s timed out. TRN: ~p", [MsgId, TRN]),
            State#state{dict = NewDict};
        error ->
            ?SYS_WARN("Unknown message timed out. TRN: ~p", [TRN]),
            % timed_out_cmd_not_in_dict
            State
    end,
    case StateName of
        wait_auth_response -> {next_state, connecting, close_and_retry(NewState)};
        _Other -> {next_state, StateName, NewState}
    end;

handle_info({timeout, retry_connect}, connecting, State) ->
    ?SYS_WARN("retry_connect timeout!", []),
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState};

%%--------------------------------------------------------------------
%% Ref keep-alive timer timeout = send keep-alive message to SMSC
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, active, State) ->
    {ok, UpdatedTRN, Message} = ucp_messages:create_cmd_31(State#state.trn, State#state.login),
    ?SYS_INFO("Sending keep-alive message: ~p", [Message]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)),
    Timer = erlang:start_timer(State#state.keepalive_interval, self(), keepalive_timeout),
    {next_state, active, State#state{keepalive_timer = Timer, trn = UpdatedTRN}};

%%--------------------------------------------------------------------
%% Cancel keepalive timer when not in active state
%%--------------------------------------------------------------------
handle_info({timeout, _Timer, keepalive_timeout}, StateName, State) ->
    ?SYS_INFO("Canceling keepalive timer", []),
    cancel_timer(State#state.keepalive_timer),
    {next_state, StateName, State};

%%--------------------------------------------------------------------
%% Ref configuration change
%%--------------------------------------------------------------------
handle_info({config_reloaded, SMSConnConfig}, StateName, State) ->
    ?SYS_INFO("UCP Connection process ~p (~p) received configuration reload notification", [State#state.name, self()]),
    NewState = State#state{
        reply_timeout = proplists:get_value(reply_timeout, SMSConnConfig, 20000),
        keepalive_interval = proplists:get_value(keepalive_interval, SMSConnConfig, 62000),
        default_originator = proplists:get_value(default_originator, SMSConnConfig, "orange.pl")
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
%% Ref state 'on entry' - provided by gen_fsm2
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

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%===================================================================
%% Cut message into pieces (if needed) then put them on the queue
%%%===================================================================
enqueue_event({send_message, {Receiver, Message, Opts}}, From, State) ->
    {ok, UpdatedCRef, Msgs} = ucp_messages:create_cmd_51_body(
                                   State#state.cref,
                                   State#state.default_originator,
                                   Receiver,
                                   Message,
                                   Opts),
    {ok, Q, Ids} = enqueue_message(Msgs, State#state.req_q, []),
    gen_fsm:reply(From, {ok, Ids}),
    gen_fsm:send_all_state_event(self(), dequeue),
    {ok, State#state{req_q = Q, cref = UpdatedCRef}};
enqueue_event(Event, From, State) ->
    ?SYS_WARN("Unknown event received from ~p: ~p", [From, Event]),
    {ok, State}.

enqueue_message([], Q, Ids) ->
    {ok, Q, lists:reverse(Ids)};
enqueue_message([H|T], Q, Ids) ->
    Id = get_message_id(),
    ?SYS_DEBUG("Enqueueing message (~s)", [Id]),
    NQ = queue:in({Id, H}, Q),
    enqueue_message(T, NQ, [Id | Ids]).

%%%===================================================================
%% Handle messages from queue
%%%===================================================================
dequeue_message(State) ->
    case is_sending_allowed(State) of
        true ->
            ?SYS_DEBUG("Dequeueing...", []),
            case queue:out(State#state.req_q) of
                {{value, Message}, Q} ->
                    case process_queued_message(Message, State#state{req_q = Q}) of
                        {_, active, NewState} ->
                            dequeue_message(NewState);
                        Res ->
                            Res
                    end;
                {empty, _} ->
                    % TODO: set keepalive timer
                    {next_state, active, State}
            end;
       false ->
            % TODO: disable keepalive timer
            ?SYS_DEBUG("Sending not allowed...", []),
            {next_state, wait_response, State}
    end.

process_queued_message({Id, Body}, State) ->
    ?SYS_INFO("Processing message (~s)", [Id]),
    case post_message(Id, Body, State) of
        {ok, NewState} ->
            StateName = case is_sending_allowed(NewState) of
                true -> active;
                false -> wait_response
            end,
            {next_state, StateName, NewState};
        {error, _Reason} ->
            Q = queue:in_r({Id, Body}, State#state.req_q),
            NewState = close_and_retry(State#state{req_q = Q}),
            {next_state, connecting, NewState}
    end.

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
            ?SYS_ERROR("Connection to ~p failed: ~p", [State#state.name, Reason]),
            NewState = close_and_retry(State),
            {ok, connecting, NewState}
    end.

post_message(MsgId, {cmd_body, CmdId, Body}, State) ->
    {ok, UpdatedTRN, Message} = ucp_utils:create_message(State#state.trn, CmdId, Body),
    ?SYS_DEBUG("Sending message (~s): ~p", [MsgId, Message]),
    case gen_tcp:send(State#state.socket, ucp_utils:wrap(Message)) of
        ok ->
            NewState = update_sending_counter(1, State),
            Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, UpdatedTRN}),
            NewDict = dict:store(UpdatedTRN, [{Timer, MsgId, Body}], NewState#state.dict),
            {ok, NewState#state{dict = NewDict, trn = UpdatedTRN}};
        Error -> Error
    end.

update_sending_counter(Value, State) ->
    UnconfirmedNo = State#state.messages_unconfirmed + Value,
    State#state{messages_unconfirmed = UnconfirmedNo}.

is_sending_allowed(State) ->
    State#state.messages_unconfirmed < State#state.sending_window_size.

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
              fun(_Id, [{Timer, Id, Msg}|_], Q) ->
                      cancel_timer(Timer),
                      queue:in_r({Id, Msg}, Q);
                 (_, _, Q) ->
                      Q
              end, State#state.req_q, State#state.dict),
    erlang:send_after(Timeout, self(), {timeout, retry_connect}),
    State#state{socket = null, req_q = Queue, dict = dict:new()}.

close_and_retry(State) ->
    close_and_retry(State, ?RETRY_TIMEOUT).

%%-----------------------------------------------------------------------
%% Deals with incoming messages
%%-----------------------------------------------------------------------
handle_received_data(Data, State) ->
    case ucp_utils:decode_message(Data) of
        {ok, Message} ->
            ?SYS_DEBUG("Processing received message: ~p", [Message]),
            NewState = process_confirmations(Message, State),
            process_message(Message, NewState);
        Error ->
            % Decoding failed = ignore message
            %TODO: Make sure is't OK?
            ?SYS_WARN("Error parsing data: ~p", [Error]),
            Error
    end.

process_confirmations({#ucp_header{o_r = "R", trn = TRN}, _Body}, State) ->
    % Update counter in state
    NewState = update_sending_counter(-1, State),
    % Cancel timers
    IntTRN = erlang:list_to_integer(TRN),
    case get_msg_rec(IntTRN, State#state.dict) of
        {Timer, MsgId, _Msg} ->
            ?SYS_DEBUG("Message ~s reception acknowledged", [MsgId]),
            cancel_timer(Timer),
            NewDict = dict:erase(IntTRN, State#state.dict),
            NewState#state{dict = NewDict};
        {error, unknown_trn} -> % message must have expired earlier = ignore
            ?SYS_WARN("Unknown TRN: ~s", TRN),
            NewState
    end;
process_confirmations(_Message, State) ->
    State.

process_message({#ucp_header{ot = "31", o_r = "R"}, _Body}, State) ->
    % just keepalive ack/nack - do nothing
    {ok, State};

process_message({#ucp_header{ot = "51", o_r = "R"}, _Body}, State) ->
    % message reception confirmation
    {ok, State};

process_message({#ucp_header{ot = "60", o_r = "R"}, Body}, State) ->
    case Body of
        #ack{} -> {auth_ok, State};
        #nack{} -> {auth_failed, Body#nack.sm, State}
    end;

process_message({Header = #ucp_header{ot = "52", o_r = "O"}, Body}, State) ->
    % respond with ACK
    ?SYS_INFO("Received message: ~p", [Body]),
    {ok, Ack} = ucp_messages:create_ack(Header),
    ?SYS_INFO("Sending ACK message: ~p", [Ack]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Ack)),
    %TODO: Check sending result = Don't know what to do when error!!
    % Ref message
    Recipient = Body#ucp_cmd_5x.adc,
    Data = Body#ucp_cmd_5x.msg,
    Sender = ucp_utils:decode_sender(Body#ucp_cmd_5x.otoa, Body#ucp_cmd_5x.oadc),
    gen_event:notify(ucp_event, {sms, {Recipient, Sender, Data}}),
    {ok, State};

process_message({Header = #ucp_header{ot = "53", o_r = "O"}, Body}, State) ->
    % respond with ACK
    Info = hex:hexstr_to_list(ucp_utils:from_ira(Body#ucp_cmd_5x.msg)),
    ?SYS_INFO("Received delivery report message: ~p", [Info]),
    {ok, Ack} = ucp_messages:create_ack(Header),
    ?SYS_INFO("Sending ACK message: ~p", [Ack]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Ack)),
    {ok, State};

process_message(Message = {Header, _Body}, State) ->
    ?SYS_DEBUG("Unhandled message: ~p", [Message]),
    {ok, Ack} = ucp_messages:create_ack(Header),
    ?SYS_INFO("Sending ACK message: ~p", [Ack]),
    gen_tcp:send(State#state.socket, ucp_utils:wrap(Ack)),
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
