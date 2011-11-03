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
-define(SEND_TIMEOUT, 1000).
-define(RETRY_TIMEOUT, 2000).
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
    gen_fsm:start_link(?MODULE, [Name, Host, Port, Login, Password], [{debug, [trace]}]).

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
    {ok, SMSConnConfig} = get_config(),
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
    {ok, connecting, State, 0}.

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
    ?SYS_INFO("Closing connection request"),
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
    case catch recvd_wait_auth_response(RawData, State) of
        ok ->
            dequeue_messages(State);
        {fail_auth, Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State, ?GRACEFUL_RETRY_TIMEOUT)};
        {'EXIT', Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State)};
        {error, Reason} ->
            report_auth_failure(State, Reason),
            {next_state, connecting, close_and_retry(State)}
    end;

handle_info({tcp, _Socket, Data}, StateName, State)
  when (StateName == active orelse StateName == active_auth) ->
    case catch recvd_packet(Data, State) of
        {response, Response, RequestType} ->
            NewState = case Response of
                       {reply, Reply, To, S1} -> gen_fsm:reply(To, Reply),
                           S1;
                       {ok, S1} ->
                           S1
                   end,
            if (StateName == active_auth andalso
                RequestType == authRequest) orelse
               (StateName == active) ->
                    dequeue_messages(NewState);
               true ->
                    {next_state, StateName, NewState}
            end;
        _ ->
            {next_state, StateName, State}
    end;

handle_info({tcp_closed, _Socket}, StateName, State) ->
    ?SYS_WARN("SMSC server closed the connection: ~p~nIn State: ~p",
                 [State#state.name, StateName]),
    {next_state, connecting, close_and_retry(State)};

handle_info({tcp_error, _Socket, Reason}, StateName, State) ->
    ?SYS_DEBUG("TCP error received: ~p~nIn State: ~p", [Reason, StateName]),
    {next_state, connecting, close_and_retry(State)};

%%
%% Timers
%%
handle_info({timeout, Timer, {cmd_timeout, Id}}, StateName, S) ->
    ?SYS_WARN("Dupa 1", []),
    case cmd_timeout(Timer, Id, S) of
        {reply, To, Reason, NewS} -> gen_fsm:reply(To, Reason),
                                     {next_state, StateName, NewS};
        {error, _Reason}           -> {next_state, StateName, S}
    end;

handle_info({timeout, retry_connect}, connecting, State) ->
    {ok, NextState, NewState} = connect(State),
    {next_state, NextState, NewState};

handle_info({timeout, _Timer, auth_timeout}, wait_auth_response, State) ->
    {next_state, connecting, close_and_retry(State)};

%%
%% Make sure we don't fill the message queue with rubbish
%%
handle_info(Info, StateName, State) ->
    ?SYS_DEBUG("Unexpected Info: ~p~nIn state: ~p~n when StateData is: ~p", [Info, StateName, State]),
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->
    ?SYS_DEBUG("~p terminating", [self()]),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
        {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
dequeue_messages(State) ->
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

process_message(State, Event, From) ->
    case send_message(Event, From, State) of
        {ok, NewState} ->
            case Event of
                {auth, _, _} ->
                    {next_state, active_auth, NewState};
                _ ->
                    {next_state, active, NewState}
            end;
        {error, _Reason} ->
            Q = queue:in_r({Event, From}, State#state.req_q),
            NewState = close_and_retry(State#state{req_q = Q}),
            {next_state, connecting, NewState}
    end.

connect(State) ->
    ?SYS_DEBUG("Connecting to ~p -> ~p:~p", [State#state.name, State#state.host, State#state.port]),
    case gen_tcp:connect(State#state.host, State#state.port, ?TCP_OPTIONS, ?CONNECTION_TIMEOUT) of
        {ok, Socket} ->
            case auth_request(State#state{socket = Socket}) of
                {ok, NewState} ->
                    Timer = erlang:start_timer(?AUTH_TIMEOUT, self(), auth_timeout),
                    {ok, wait_auth_response, NewState#state{socket = Socket, auth_timer = Timer}};
                {error, Reason} ->
                    report_auth_failure(State, Reason),
                    {ok, connecting, close_and_retry(State)}
            end;
            %TODO: implement keepalive
            %spawn_link(fun() -> keepalive(NState) end),
            %ucp_conn_pool:add_member(self()),
        {error, Reason} ->
            ?SYS_ERROR("SMSC connection ~p failed: ~p", [State#state.name, Reason]),

            NewState = close_and_retry(State),
            {ok, connecting, NewState}
    end.

report_auth_failure(State, Reason) ->
    ?SYS_WARN("SMSC authentication failed on ~s: ~p", [State#state.name, Reason]).

auth_request(State) ->
    TRN = get_next_trn(State),
    {ok, UcpMessage} = ucp_messages:create_m60(TRN, State#state.login, State#state.pass),
    send_message(State#state{trn = TRN}, UcpMessage).

send_message(_Event, _From, _State) ->
    ok.

send_message(State, Message) ->
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
        ok -> {ok, State};
            Timer = erlang:start_timer(?CMD_TIMEOUT, self(), {cmd_timeout, Id}),
            New_dict = dict:store(Id, [{Timer, Message, "From", "Name"}], S#eldap.dict),
            %New_dict = dict:store(Id, [{Timer, Command, From, Name}], S#eldap.dict),
            {ok, State#state{trn = TRN, dict = New_dict}};
        Error -> Error
    end.

%handle_call(make_error, _From, State) ->
    %i_want_to_die = right_now,
    %{reply, ok, State};

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

%handle_call(terminate, _From, State) ->
    %?SYS_DEBUG("SMSC ~p received terminate call, disabled in configuration", [State#state.unique_name]),
    %{stop, normal, State};

%handle_info({tcp, Socket, RawData}, State) ->
    %handle_data(Socket, RawData),
    %{noreply, State};

%% handle connection termination
%handle_info({tcp_closed, _Socket}, State) ->
    %lager:info("Connection closed by peer.~n"),
    %{stop, normal, State};

%handle_info(timeout, #state{lsock = LSock} = State) ->
    %{ok, _Sock} = gen_tcp:accept(LSock),
    %smsc_simulator_sup:start_child(),
    %{noreply, State};

%handle_info(Any, State) ->
    %lager:info("Unhandled message: ~p~n", [Any]),
    %{noreply, State}.

handle_data(_Socket, RawData) ->
    lager:info("Received data: ~p~n", [RawData]),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% KeepAlive function, should by spawned
%%
%% @spec keepalive(State) -> exit() | keepalive(State)
%% @end
%%--------------------------------------------------------------------

keepalive(_State) ->
    ok.
    % TODO: Need refactor
    %receive
    %after State#state.keepalive_time ->
            %Seq = get_next_seq(State#state.seq),
            %{ok, UcpMessage} =
                %ucp_messages:create_m31(Seq, State#state.login),
            %case send_message(State, UcpMessage, keepalive) of
                %{ok, NState, _ErrMsg} -> keepalive(NState#state{seq = Seq});
                %{error, NState, ErrMsg} ->
                    %?SYS_ERROR("SMSC keepalive problem (~s), reconnecting", [ErrMsg]),
                    %{ok, RState} = smsc_reconnect(NState),
                    %update_state(RState),
                    %keepalive(RState)
            %end
    %end.


%case gen_tcp:recv(Socket, 0, State#state.reply_timeout) of
    %{ok, Data} ->
        %UcpMessages = binary:split(Data,[<<3>>],[global]),
        %AnalyzeOutput = analyze_ucp_message(UcpMessages, UName),
        %case lists:member(ack, AnalyzeOutput) of
            %true ->
                %{ok, State, ok};
            %false ->
                %{error, State, "Not received ACK"}
        %end;

analyze_ucp_message(UcpMessage) ->
    {ok, {Header, Body}} = ucp_utils:unpackUCP(UcpMessage),
    ?SYS_DEBUG("Header: ~p~nBody: ~p~n", [Header, Body]),
    {Type, Error} = ucp_utils:analyze_ucp_body(Body),
    Body.

% TODO: replace with real configuration
get_config() ->
    SMSConnConfig = [
        {smsc_reply_timeout, 20000},
        {smsc_default_originator, "orange.pl"},
        {smsc_keepalive_time, 60000},
        {smsc_reconnect_time, 20000},
        {smsc_send_interval, 200}],
    {ok, SMSConnConfig}.

get_next_seq(#state{seq = Seq}) when Seq > ?MAX_MESSAGE_SEQ ->
    ?MIN_MESSAGE_SEQ;
get_next_seq(#state{seq = Seq}) ->
    Seq + 1.

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
%% recvd_wait_auth_response packet
%% Deals with incoming packets in the wait_auth_response state
%% Will return one of:
%%  ok - Success - move to active state
%%  {auth_failed, Reason} - Failed
%%  {error, Reason}
%%  {'EXIT', Reason} - Broken packet
%%-----------------------------------------------------------------------
recvd_wait_auth_response(Data, State) ->
    case ucp_utils:decode_message(Data) of
        {ok, {Header, Body}} ->
             check_trn(Header#ucp_header.trn, State#state.trn),
             check_auth_result(Body);
        Else ->
             {auth_failed, Else}
    end.

check_auth_result(Result) when is_record(Result, ack) ->
    auth_ok;
check_auth_result(Result) when is_record(Result, nack) ->
    {auth_failed, Result#nack.sm}.

check_trn(TRN, TRN) -> ok;
check_trn(_, _)   -> throw({error, wrong_auth_trn}).

ucp_decode(Data) ->
    [UcpMessage|_] = binary:split(Data, [<<3>>], [global]),
    {_Header, Body} = ucp_utils:unpackUCP(UcpMessage).


%%-----------------------------------------------------------------------
%% recvd_packet
%% Deals with incoming packets in the active state
%% Will return one of:
%%  {ok, NewS} - Don't reply to client yet as this is part of a search
%%               result and we haven't got all the answers yet.
%%  {reply, Result, From, NewS} - Reply with result to client From
%%  {error, Reason}
%%  {'EXIT', Reason} - Broke
%%-----------------------------------------------------------------------
recvd_packet(_Pkt, S) ->
    {ok, S}.
    %case asn1rt:decode('ELDAPv3', 'LDAPMessage', Pkt) of
        %{ok,Msg} ->
            %Op = Msg#'LDAPMessage'.protocolOp,
            %%?SYS_DEBUG("~p",[Op]),
            %Dict = S#eldap.dict,
            %Id = Msg#'LDAPMessage'.messageID,
            %{Timer, From, Name, Result_so_far} = get_op_rec(Id, Dict),
            %Answer =
                %case {Name, Op} of
                    %{searchRequest, {searchResEntry, R}} when
                          %is_record(R,'SearchResultEntry') ->
                        %New_dict = dict:append(Id, R, Dict),
                        %{ok, S#eldap{dict = New_dict}};
                    %{searchRequest, {searchResDone, Result}} ->
                        %Reason = Result#'LDAPResult'.resultCode,
                        %if
                            %Reason==success; Reason=='sizeLimitExceeded' ->
                                %{Res, Ref} = polish(Result_so_far),
                                %New_dict = dict:erase(Id, Dict),
                                %cancel_timer(Timer),
                                %{reply, #eldap_search_result{entries = Res,
                                                             %referrals = Ref}, From,
                                 %S#eldap{dict = New_dict}};
                            %true ->
                                %New_dict = dict:erase(Id, Dict),
                                %cancel_timer(Timer),
                                %{reply, {error, Reason}, From, S#eldap{dict = New_dict}}
                        %end;
                    %{searchRequest, {searchResRef, R}} ->
                        %New_dict = dict:append(Id, R, Dict),
                        %{ok, S#eldap{dict = New_dict}};
                    %{addRequest, {addResponse, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{delRequest, {delResponse, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{modifyRequest, {modifyResponse, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{modDNRequest, {modDNResponse, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{bindRequest, {bindResponse, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_bind_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{extendedReq, {extendedResp, Result}} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %Reply = check_extended_reply(Result, From),
                        %{reply, Reply, From, S#eldap{dict = New_dict}};
                    %{OtherName, OtherResult} ->
                        %New_dict = dict:erase(Id, Dict),
                        %cancel_timer(Timer),
                        %{reply, {error, {invalid_result, OtherName, OtherResult}},
                         %From, S#eldap{dict = New_dict}}
                %end,
            %{response, Answer, Name};
        %Error -> Error
    %end.

%check_reply(#'LDAPResult'{resultCode = success}, _From) ->
    %ok;
%check_reply(#'LDAPResult'{resultCode = Reason}, _From) ->
    %{error, Reason};
check_reply(_Other, _From) ->
    ok.
    %{error, Other}.

%check_bind_reply(#'BindResponse'{resultCode = success}, _From) ->
    %ok;
%check_bind_reply(#'BindResponse'{resultCode = Reason}, _From) ->
    %{error, Reason};
%check_bind_reply(_Other, _From) ->
%    ok.
    %{error, Other}.

%%-----------------------------------------------------------------------
%% Sort out timed out commands
%%-----------------------------------------------------------------------
cmd_timeout(Timer, Id, State) ->
    Dict = State#state.dict,
    case dict:find(Id, Dict) of
        {ok, [{Timer, _Command, From, Name}|_Res]} ->
            NewDict = dict:erase(Id, Dict),
            {reply, From, {error, timeout}, State#state{dict = NewDict}};
        error ->
            {error, timed_out_cmd_not_in_dict}
    end.
