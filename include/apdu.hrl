-author('soda@t61p').

-define(SPI_NO_RC_CC_DS,                          2#00000000).      %% 00 00
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



-record(apdu, {
          tag,                 %% b
          length,              %% b or 2b
          device_identity_tlv, %% 4b
          address_tlv,         %% 4-13b -> address_tlv
          sms_tpdu             %% 15-166b
         }).

-record(device_tlv, {
          tag,                 %% b
          length,              %% b
          source,              %% b
          destination          %% b
         }).

-record(tp_address, {
          length,              %% b
          ton_npi,             %% b
          address              %% up to 10b
         }).


-record(tpdu, {
          tag,                 %% b
          length,              %% 2b
          mti_mms_udhl_rp,
          address_len,         %% b
          ton_npi,             %% b
          address_value,       %% 0-10 byte
          tp_pid,              %% b
          tp_dcs,              %% b
          tp_scts,             %% 7b
          tp_udl,              %% integer?
          tp_ud                %% up tp 140b -> command_packet
         }).

-record(tpud, {
          udhl,                %% b
          ieia,                %% b
          iedla,               %% b
          cpl,                 %% 2b
          chl,                 %% b
          spi,                 %% 2b
          kic,                 %% b
          kid,                 %% b
          tar,                 %% 3b
          cntr,                %% 5b
          pcntr,               %% 1b
          rc_cc_ss,            %% 0/4/8b
          secured_data         %% ?
         }).

-record(concatenated_tpud, {
          udl,                 %% Indicates the length of the entire SM
          udhl,                %% b he first octet of the content or User Data part of the
                               %% Short Message itself. Length of the total
                               %% User Data Header, in this case, includes
                               %% the length of IEIa + IEIDLa + IEDa + IEIb + IEIDLb + IEDb
          ieia,                %% b [00] identifies this Header as a concatenation
                               %% control header defined in TS 23.040 [3].
          ieidla,              %% b ength of the concatenation control header (= 3).
          ieida,               %% 3b These octets contain the reference number,
                               %% sequence number and total number of
                               %% messages in the sequence, as defined in TS 23.040 [3].
          ieib,                %% Identifies this element of the UDH as
                               %% the Command Packet Identifier. CPI=70
          ieidlb,              %% Length of this object, in this case the
                               %% length of IEDb alone, which is zero,
                               %% indicating that IEDb is a null field.
          %% iedb,                %% Null field.
          cpl,                 %% Length of the Command Packet (CPL),
                               %% coded over 2 octets, and shall not be
                               %% coded according to ISO/IEC 7816-6 [8].
          %% chi,                 %% (CHI) Null field.
          chl,                 %% Length of the Command Header (CHL),
                               %% coded over one octet, and shall not be
                               %% coded according to ISO/IEC 7816-6 [8].
          spi,                 %% The remainder of the Command Header. Security Parameter Indicator
          kic,                 %% Key and algorithm Identifier for ciphering.
          kid,                 %% Key and algorithm Identifier for RC/CC/DS.
          tar,                 %% Coding is application dependent.
          cntr,                %% Replay detection and Sequence Integrity counter.
          pcntr,               %% This indicates the number of padding octets used
                               %% for ciphering at the end of the secured data.
          rc_cc_ss,            %% Length depends on the algorithm. A typical value is 8 octets if
                               %% used, and for a DS could be 48 or more octets; the minimum
                               %% should be 4 octets.


          secured_data_part    %% Contains the first portion of the Secured Data.
                               %% The remaining Secured Data will be contained
                               %% in subsequent concatenated short messages.

         }).
