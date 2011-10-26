-ifndef(smsc_retry).
-define(smsc_retry,true).

-record(smsc_retry, {
          reqid,
          receiver,
          message,
          first_fail
         }).
-endif.

