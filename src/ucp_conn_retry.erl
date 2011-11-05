%% FIXME - this module is probably obsolete now
-module(ucp_conn_retry).
-author('rafal.galczynski@jtendo.com').

-include_lib("stdlib/include/qlc.hrl").
-include("smsc_retry.hrl").
-include("logger.hrl").
-include("utils.hrl").


-export([
         start/0,
         init_once/0,
         start_retry/2,
         compare/2,
         resend/2,
         get_time_delta/1,
         start_retry_now/0,
         select_all/0
        ]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initialize function from smsc retry process
%%
%% @spec init_once() -> ok
%% @end
%%--------------------------------------------------------------------

init_once() ->
    ?SYS_DEBUG("~p", ["Initializing smsc_retry table"]),
    mnesia:create_table(smsc_retry,
                        [{ram_copies, [node()]},
                         {local_content, true},
                         {attributes, record_info(fields, smsc_retry)}]).

start() ->
    ?SYS_DEBUG("~p", ["Waiting for smsc_retry table"]),
    case mnesia:wait_for_tables([smsc_retry], 2000) of
        ok ->
            ?SYS_DEBUG("~p", ["smsc_retry table found"]),
            case load_config() of
                {ok, SMSConnConfig} ->
                    ReplyTimeout = proplists:get_value(sms_resend_timeout, SMSConnConfig, 20000),
                    ValidityTime = proplists:get_value(sms_validity_timeout, SMSConnConfig, 20000),
                    spawn(smsc_retry, start_retry, [ReplyTimeout, ValidityTime]);
                {error, smsc_config_corrupted} ->
                    ?SYS_ERROR("~p", ["Error in smsc_conn.conf, stoping!!!"]),
                    {error, smsc_config_corrupted}
            end;
        Error ->
            {error, Error}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Loop for starting resending stored sms messages
%%
%% @spec start_retry(ReplyTimeout, ValidityTime) -> ok
%% @end
%%--------------------------------------------------------------------

start_retry(ReplyTimeout, ValidityTime) ->
    receive
    after ReplyTimeout
              ->
            case select_all() of
                {error, Reason} ->
                    ?SYS_ERROR("Error getting messages to resend : ~p",[Reason]);
                ToSend ->
                    lists:foreach(
                      fun(Elem) -> resend(Elem, ValidityTime) end,
                      ToSend)
            end

    end,
    start_retry(ReplyTimeout, ValidityTime).


start_retry_now() ->
    case select_all() of
        {error, Reason} ->
            ?SYS_ERROR("Error getting messages to resend : ~p",[Reason]);
        ToSend ->
            lists:foreach(
              fun(Elem) -> resend(Elem, 1000000) end,
              ToSend)
    end.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function used for sending stored messages as records
%%
%% @spec resend(Rec, ValidityTime) -> ok
%% @end
%%--------------------------------------------------------------------

resend(Rec, ValidityTime) ->
    ?SYS_DEBUG("~s| Trying to resend message: ~p to ~p",[
                                                         Rec#smsc_retry.reqid,
                                                         Rec#smsc_retry.message,
                                                         Rec#smsc_retry.receiver]),
    {smsc_retry, ReqId, Receiver, Message, FirstTry} = Rec,
    case compare(get_time_delta(FirstTry), ValidityTime) of
        greater ->
            ?SYS_DEBUG("~s| Message validity time expired - deleting",[Rec#smsc_retry.reqid]),
            mnesia:dirty_delete_object(Rec),
            ok;
        _Else ->
            ?SYS_DEBUG("~s| Resending message: ~p to ~p",[
                                                          Rec#smsc_retry.reqid,
                                                          Rec#smsc_retry.message,
                                                          Rec#smsc_retry.receiver]),
            case smsc_pool:send_message(Receiver, Message, ReqId) of
                {ok,ok} ->
                    ?SYS_DEBUG("~s| Message sent - deleting", [Rec#smsc_retry.reqid]),
                    mnesia:dirty_delete_object(Rec),
                    ok;
                _NotOk ->
                    ?SYS_DEBUG("~s| Error resending message: ~p to ~p",[
                                                                        Rec#smsc_retry.reqid,
                                                                        Rec#smsc_retry.message,
                                                                        Rec#smsc_retry.receiver]),
                    error
            end
    end.



do(Q) ->
    F = fun() -> qlc:e(Q) end,
    {atomic, Val} = mnesia:transaction(F),
    Val.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function used for getting all waiting messages from mnesia db
%%
%% @spec select_all() -> []
%% @end
%%--------------------------------------------------------------------

select_all() ->
    do( qlc:q(
            [ X || X <- mnesia:table(smsc_retry) ]
        )).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function calculating TimeDelta between last send and now
%%
%% @spec get_time_delta(Time) -> Int
%% @end
%%--------------------------------------------------------------------

get_time_delta(FirstTry) ->
    First = calendar:datetime_to_gregorian_seconds(FirstTry),
    Now = calendar:datetime_to_gregorian_seconds(erlang:localtime()),
    Now-First.

compare(X, Y) ->
    if X>Y -> greater;
       X==Y -> equal;
       true -> less
    end.

load_config(Filename) ->
    ?SYS_INFO("Loading SMSC connection configuration: ~s", [Filename]),
    case file:consult(?PRIV(Filename)) of
        {ok, SMSCConf} ->
            {ok, SMSCConf};
        {error, Reason} ->
            ?SYS_FATAL("Error loading configuration file (~s): ~p", [Filename, Reason]),
            {error, {smsc_config_corrupted, Filename, Reason}}
    end.

load_config() ->
    case load_config("smsc_conn.conf") of
        {ok, SMSConfig} ->
            {ok, SMSConfig};
        {error, {smsc_config_corrupted, Filename, Reason}} ->
            ?SYS_FATAL("Error loading configuration file (~s): ~p", [Filename, Reason]),
            {error, smsc_config_corrupted}
    end.
