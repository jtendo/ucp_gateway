Erlang UCP Gateway
==================

Project status
--------------
Actually it's more of a SMSC client than a real gateway at the moment.

Tested with SMSC LogicaCMG's EMI/UCP interface 4.6

If you like this project, you might also be interested in [jtendo UCP Simulator](https://github.com/jtendo/ucp_simulator)

Usage
-----

1. Install:

    `rebar get-deps compile` or add a rebar dependency to your application
    
2. Edit sample configuration located in `conf.sample` directory
3. Move the configuration folder to the right spot:

    ```
    $ mv conf.sample conf
    ```
    
    or
    
    ```
    $ mv conf.sample yourapp/conf
    ```
    
4. Typical API usage:

    a) Send messages:

    ```erlang
    Pid = ucp_conn_pool:get_active_connection(),
    Message = "Hello world", %% binary messages are also supported
    Opts = [
      {split, true},
      {notification_request, true}
    ],
    ucp_conn:send_message(Pid, Msisdn, Message, Opts).
    
    ```
    
    The interface is asynchronous. Currently, messages are send using "one-shot" mode, requiring SMSC to ack.
    This will be made optional.

    b) Receive messages:

    ```erlang
    -module(my_receiver).
    -behaviour(gen_event).
    
    %% (...)
    
    attach() ->
        ucp_event:add_handler(?MODULE).
        
    handle_event({sms, {Recipient, Sender, Data} = Msg}, State) ->
        io:format("Received: ~p~n", [Msg]),
        {ok, State};
        
    %% (...)
    ```
    
    ```
    
    
License
-------
BSD License -- http://www.opensource.org/licenses/bsd-license.php

    
TODO
----

- Documentation
- Detailed examples
- Message routing
- Allow message buffering in SMSC
- ...