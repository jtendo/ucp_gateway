-ifndef(ucp_syntax).
-define(ucp_syntax, true).

-record(header, {
          trn = 0,
          %% Transaction reference number, right justified with leading zero.
          len = 0,
          %% Total number of IRA characters contained
          %% between stx and etx, right justified with leading zeros.
          o_r = "",
          %% “O” indicates operation, “R” indicates result
          ot = ""
          %% Operation Type
          %% 01 Call input operation
          %% 02 Multiple address call input operation
          %% 03 Call input with supplementary services operation
          %% 30 SMS message transfer operation
          %% 31 SMT alert operation
          %% 5x 50-series, see chapter 5, 7
          %% 6x 60-series, see chapter 6, 7
         }).
-record(ucp5x, {
          adc = "", %% Address code recipient for the SM OadC 16 Num.
          %% String Address code originator
          %% If the OTOA field indicates alphanumeric OAdC.
          %% A 22 character string corresponds with a max. 11 character alphanumeric string.
          oadc = "", %% Address code originator, maximum length is 16 digits.
          ac = "", %% Authentication code originator (min 4 char., max 16 char)
          nrq = "", %% Notification Request 0 = NAdC not used 1 = NAdC used
          nadc = "", %% Notification Address
          nt = "", %% Notification Type1:
          %% Buffered message notification (BN),
          %% Delivery Notification (DN),
          %% Non-delivery notification (ND),
          %% 0 default value, 1 = DN, 2 = ND, 3 = DN+ND, 4 = BN, 5 = BN+DN, 6 = BN+ND, 7 = all.
          npid = "", %% Notification PID value:
          %% 0100	Mobile Station
          %% 0122	Fax Group 3
          %% 0131	X.400
          %% 0138	Menu over PSTN
          %% 0139	PC appl. over PSTN (E.164)
          %% 0339	PC appl. over X.25 (X.121)
          %% 0439	PC appl. over ISDN (E.164)
          %% 0539	PC appl. over TCP/IP
          lrq = "", %% Last Resort Address request: 0 = LRAd not used 1 = LRAd used
          lrad = "", %% Last Resort Address
          lpid = "",  %% LRAd PID value:
          %% 0100	Mobile Station
          %% 0122	Fax Group 3
          %% 0131	X.400
          %% 0138	Menu over PSTN
          %% 0139	PC appl. over PSTN (E.164)
          %% 0339	PC appl. over X.25 (X.121)
          %% 0439	PC appl. over ISDN (E.164)
          %% 0539	PC appl. over TCP/IP
          dd = "", %% Deferred Delivery requested: 0 = DDT not used 1 = DDT used
          ddt = "", %% Deferred delivery time in DDMMYYHHmm
          vp = "", %% Validity period in DDMMYYHHmm
          rpid = "", %% Replace PID2, value 0000...0071, 0095,
          %% 0127(SIM Data Download), 0192...0255.
          scts = "", %% Service Centre Time Stamp in DDMMYYHHmmss.
          %% For a Short Message this is the time stamp of the Short Message itself.
          %% For a Notification this is the time stamp of the corresponding Short Message.
          dst = "", %% Delivery status:
          %% 0 = delivered
          %% 1 = buffered (see Rsn)
          %% 2 = not delivered (see Rsn)
          rsn = "", %% Reason code, value '000'...'255'.
          %% Code can be found in an SMSC configuration file witch can be
          %% changed by the operator. (See appendix A)
          dscts = "", %% Delivery time stamp in DDMMYYHHmmss.
          %% Indicates the actual time of delivery of the Short Message.
          mt="3", %% Message Type. Associated parameters depend on the value of MT.
          nb = "",
          msg = "",
          mms = "", %% More Messages to Send (to the same SME)
          pr = "", %% Priority Requested
          dcs = "", %% Deprecated. Data Coding scheme:
          %% 0 = default alphabet
          %% 1 = user defined data ('8 bit')
          mcls = "", %% Message Class:
          %% 0 = message class 0
          %% 1 = message class 1
          %% 2 = message class 2
          %% 3 = message class 3
          rpi = "", %% Reply Path:
          %% 1 = request
          %% 2 = response
          cpg = "", %% (reserved for Code Page)
          rply = "", %% (reserved for Reply type)
          otoa="5039", %% Originator Type Of Address:
          %% 1139 The OadC is set to NPI telephone and TON international.
          %% 5039 The OAdC contains an alphanumeric address (see OAdC and below).
          %% Leave OTOA empty for a numeric address in the OAdC.
          hplmn = "", %% Home PLMN Address
          xser = "", %% Extra Services
          %%           With the XSer field one or more additional services can be specified.
          %% These services consist of IRA encoded data constructed in the
          %% following common format: TTLLDD...
          %% TT: represents two HEX characters defining the type of service.
          %% For a description of available services refer to section “Description Of XSer Extra Services”
          %% LL: represents two HEX characters defining the number of octets
          %% present in the data field DD.
          %% (Note that the number of HEX characters in the data DD is twice the number of octets)
          %% DD...: represents a stream of HEX characters defining the service specific data itself.
          %% If more than one additional service is to be specified in one message,
          %% this service information is concatenated without any separators, i.e.
          %% TT1LL1DD1...DD1TT2LL2DD2..DD2
          %% The above construction is designed such that in the
          %% future additional service types can be added to the XSer field.
          res4 = "", %% (reserved for future use)
          res5 = "", %% (reserved for future use)
          crc = ""
         }).



-record(ucp60, {
          oadc = "",
          %% Any valid X.121, E164, TCP/IP or abbreviated address, excluding prefixes
          oton = "", %% Originator Type of Numbering
          %% 1 = International number (starts with the country code)
          %% 2 = National number (default value if omitted)
          %% 6 = Abbreviated number (short number alias)
          onpi = "", %% Originator Numbering Plan Id:
          %% 1 = E.164 address (default value if omitted)
          %% 3 = X121 address
          %% 5 = Private (TCP/IP address/abbreviated number address)
          styp = "", %% Subtype of operation:
          %% 1 = open session
          %% 2 = reserved
          %% 3 = change password
          %% 4 = open provisioning session
          %% 5 = reserved
          %% 6 = change provisioning password
          pwd = "", %% Current password encoded into IRA characters,
          npwd = "", %% New password encoded into IRA characters
          vers = "", %% Version number 0100'
          ladc = "", %% Address to be filled in, removed from or checked in a
          %% VSMSC list, containing a valid X.121, E.164
          %% or TCP/IP address excluding prefixes
          lton = "", %% Type of Number list address:
          %% 1 = International number (starts with the country code)
          %% 2 = National number (default value if omitted)
          lnpi = "", %%  Numbering Plan Id list address
          opid = "", %% Originator Protocol Identifier: 00 = Mobile station 39 = PC application

          res1 = "",
          crc = ""
         }).


-record(ucp61, {
%%% header =  #header{},
          oadc = "", %% Any valid X.121, E164, TCP/IP or abbreviated address, excluding prefixes
          oton = "", %% Originator Type of Number:
          %% 1 = International number (starts with the country code)
          %% 2 = National number (default value if omitted)
          %% 6 = Abbreviated number (short number alias)
          onpi = "", %% Originator Numbering Plan Id:
          %% 1 = E.164 address (default value if omitted)
          %% 3 = X121 address
          %% 5 = Private (TCP/IP address/abbreviated number address)
          styp = "", %% Subtype of operation:
          %% 1 = open session
          %% 2 = reserved
          %% 3 = change password
          %% 4 = open provisioning session
          %% 5 = reserved
          %% 6 = change provisioning password
          pwd = "", %% Current password encoded into IRA characters,
          npwd = "", %% New password encoded into IRA characters
          vers = "", %% Version number 0100'
          ladc = "", %% Address to be filled in, removed from or checked in a
          %% VSMSC list, containing a valid X.121, E.164
          %% or TCP/IP address excluding prefixes
          lton = "", %% Type of Number list address:
          %% 1 = International number (starts with the country code)
          %% 2 = National number (default value if omitted)
          lnpi = "",
          res1 = "",
          res2 = "",
          crc = ""
         }).

-record(ucp31,{
          adc = "", %% Address code for the SMT, maximum length is 16 digits.
          pid = "", %% SMT 0100	Mobile Station
          %% 0122	Fax Group 3
          %% 0131	X.400
          %% 0138	Menu over PSTN
          %% 0139	PC appl. via PSTN
          %% 0339	PC appl. via X.25
          %% 0439	PC appl. via ISDN
          %% 0539	PC appl. via TCP/IP
          %% 0639.....PC appl. via abbreviated number
          crc = ""
         }).

-record(ack,{
          ack = "", %% Positive acknowledgement Char A
          sm = "", %% System message , String
          mvp = "",
          crc = ""
         }).

-record(nack, {
          nack = "", %% Negative acknowledgement
          ec = "", %% Error Code, 2 Chars
          sm = "", %% System message , String
          crc = ""

         }).
-endif. %% -ifndef(ucp_syntax)
