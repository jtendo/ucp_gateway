-author('soda@t61p').

-define(SPI_NO_RC_CC_DS,                          2#00000000). %% 00 00
-define(SPI_RC,                                   2#00000001). %% 00 01
-define(SPI_CC,                                   2#00000010). %% 00 02
-define(SPI_DS,                                   2#00000011). %% 00 03
-define(SPI_NO_ENCRYPTION,                        2#00000000). %% 00 00
-define(SPI_ENCRYPTION,                           2#00000100). %% 00 04

-define(SPI_NO_COUNTER,                           2#00000000). %% 00 00
-define(SPI_COUNTER_AVAILABLE_NOT_CHECKED,        2#00001000). %% 00 08
-define(SPI_COUNTER_PROCESS_IF_HIGHER_THEN_RE,    2#00010000). %% 00 10
-define(SPI_COUNTER_PROCESS_IF_ONE_MODE_THEN_RE,  2#00011000). %% 00 18

-define(SPI_NO_POR,                               2#00000000). %% 00 00
-define(SPI_POR_TO_SE,                            2#00000001). %% 01 00
-define(SPI_POR_ON_ERROR,                         2#00000010). %% 02 00
-define(SPI_POR_RESERVED,                         2#00000011). %% 03 00

-define(SPI_POR_NO_RC_CC_DS,                      2#00000000). %% 00 00
-define(SPI_POR_WITH_RC,                          2#00000100). %% 04 00
-define(SPI_POR_WITH_CC,                          2#00001000). %% 08 00
-define(SPI_POR_WITH_DS,                          2#00001100). %% 0c 00

-define(SPI_POR_NOT_ENCRYPTED,                    2#00000000). %% 00 00
-define(SPI_POR_ENCRYPTED,                        2#00010000). %% 10 00

-define(SPI_POR_SMS_DELIVER_REPORT,               2#00000000). %% 00 00
-define(SPI_POR_SMS_SUBMIT,                       2#00100000). %% 20 00

-define(KIC_ALGORITHM_KNOWN,                     2#00000000).
-define(KIC_ALGORITHM_DES,                       2#00000001).
-define(KIC_ALGORITHM_RESERVED,                  2#00000010).
-define(KIC_ALGORITHM_PROPRIETARY,               2#00000011).

-define(KIC_ALGORITHM_DES_CBS,                   2#00000000).
-define(KIC_ALGORITHM_3DES2,                     2#00000100).
-define(KIC_ALGORITHM_3DES3,                     2#00001000).
-define(KIC_ALGORITHM_KID_RESERVED,              2#00001100).

-define(KID_ALGORITHM_KNOWN,                     2#00000000).
-define(KID_ALGORITHM_DES,                       2#00000001).
-define(KID_ALGORITHM_RRESERVED,                 2#00000010).
-define(KID_ALGORITHM_PROPRIETARY,               2#00000011).

-define(KID_ALGORITHM_DES_CBS,                   2#00000000).
-define(KID_ALGORITHM_3DES2,                     2#00000100).
-define(KID_ALGORITHM_3DES3,                     2#00001000).
-define(KID_ALGORITHM_KID_RESERVED,              2#00001100).

-define(ZERO_IV,                                 <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>).

-record(sim_profile, {
          spi,
          kic,
          kid,
          kic_key1,
          kic_key2,
          kic_key3,
          kid_key1,
          kid_key2,
          kid_key3
         }).

-record(tpud, {
          cpl,                 %% 2b
          chl,                 %% b
          spi,                 %% 2b
          kic,                 %% b
          kid,                 %% b
          tar,                 %% 3b
          cntr,                %% 5b
          pcntr,               %% 1b
          rc_cc_ss,            %% 0/4/8b
          data                 %% ?
         }).
