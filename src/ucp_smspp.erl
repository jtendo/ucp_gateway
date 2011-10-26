-module(ucp_smspp).
-author('rafal.galczynski@jtendo.com').

-include("../include/apdu.hrl").
-include("../include/logger.hrl").
-compile([export_all]).
-compile([debug_info]).

t() ->
    %% Data = <<16#80, 16#EF, 16#57, 16#9B, 16#AE, 16#EC, 16#BE, 16#69,
    %%          16#41, 16#A6, 16#DC, 16#0D, 16#43, 16#7D, 16#55, 16#3F,
    %%          16#E1, 16#20, 16#02, 16#67, 16#65, 16#CF, 16#49, 16#7D,
    %%          16#EE, 16#5D>>,
    Data = <<16#03, 16#10, 16#00, 16#60, 16#02, 16#00, 16#1A, 16#4D,
             16#3A, 16#20, 16#35, 16#30, 16#31, 16#30, 16#30, 16#30,
             16#30, 16#30, 16#30, 16#20, 16#4F, 16#3A, 16#20, 16#4F,
             16#72, 16#61, 16#6E, 16#67, 16#65, 16#20, 16#4F, 16#6E,
             16#65, 16#03, 16#00, 16#0C, 16#04, 16#00, 16#4E, 16#6F,
             16#77, 16#79, 16#20, 16#6E, 16#75, 16#6D, 16#65, 16#72,
             16#03, 16#00, 16#0E, 16#05, 16#00, 16#5A, 16#6D, 16#69,
             16#65, 16#6E, 16#20, 16#6F, 16#66, 16#65, 16#72, 16#74,
             16#65, 16#00, 16#00, 16#20, 16#F6, 16#00, 16#00, 16#1C,
             16#FF, 16#00, 16#19, 16#01, 16#61, 16#61, 16#61, 16#61,
             16#61, 16#61, 16#61, 16#61, 16#61, 16#61, 16#61, 16#61,
             16#61, 16#61, 16#61, 16#61, 16#61, 16#61, 16#61, 16#61,
             16#61, 16#61, 16#61, 16#61>>,
    XX = smspp:create_tpud_message(Data),
    [binpp:pprint(X) || X <- XX].


create_tpud_message(Data) when is_binary(Data)->
    KIC1 = ?KIC_ALGORITHM_KNOWN bor ?KIC_ALGORITHM_3DES2 bor 2#100000, %% key id
    KID1 = ?KID_ALGORITHM_KNOWN bor ?KID_ALGORITHM_3DES2 bor 2#100000, %% key id
    %% Key1 = <<16#30, 16#42, 16#30, 16#42, 16#30, 16#44, 16#30, 16#44, 16#30, 16#45, 16#30, 16#45, 16#30, 16#46, 16#30, 16#46>>,
    Key1 = <<16#01,16#23,16#45,16#67,16#89,16#ab,16#cd,16#ef>>,
    Key2 = <<16#02,16#23,16#45,16#67,16#89,16#ab,16#cd,16#ef>>,

    %% TAR = <<16#52, 16#41, 16#44>>, %% Toolkit Application Reference (TAR): 3 octets.
    TAR = <<16#44, 16#41, 16#52>>, %% Toolkit Application Reference (TAR): 3 octets.
    SPIA =
        ?SPI_CC bor
        ?SPI_ENCRYPTION bor
        ?SPI_NO_COUNTER,
    SPIB =
        ?SPI_POR_TO_SE bor
        ?SPI_POR_NO_RC_CC_DS bor
        ?SPI_POR_NOT_ENCRYPTED bor
        ?SPI_POR_SMS_DELIVER_REPORT,
    SPI = <<SPIA, SPIB>>,
    CNTR = <<16#00, 16#00, 16#00, 16#00, 16#00>>, %% (Counter): 5 octets, counter management

    RCCCSS = <<16#D8, 16#0C, 16#AB, 16#B2,
               16#C3, 16#F3, 16#90, 16#3D>>,
    SecureData = encrypt_data(Key1, Key2, ucp_utils:pad_to(8,Data)),
    PCNTR = size(ucp_utils:pad_to(8,Data)) - size(Data),
    %% 140 - 24 = 116
    case size(Data) =< 116 of
        true ->
            create_tpud(#tpud{
               udhl =  <<16#02>>, %% 02h  [
               ieia =  <<16#70>>, %% 70h  [ UDH Command packet
               iedla = <<16#00>>, %% 00h [
               spi = SPI,
               kic = <<KIC1>>,
               kid = <<KID1>>,
               tar = TAR,
               cntr = CNTR,
               pcntr = <<PCNTR>>,
               rc_cc_ss = RCCCSS,
               secured_data = SecureData});
        false ->
            DataParts = ucp_utils:binary_split(SecureData,140),
            Sec = 1,
            Act = 1,
            Tot = length(DataParts),
            Tpuds = create_tpud_concatenated(
                      #concatenated_tpud{ieia = <<00>>,
                                         ieidla = <<03>>,
                                         ieida = <<Sec,Act,Tot>>,
                                         ieidlb = <<00>>,
                                         ieib = <<70>>,
                                         spi = SPI,
                                         kic = <<KIC1>>,
                                         kid = <<KID1>>,
                                         tar = TAR,
                                         cntr = CNTR,
                                         pcntr = <<PCNTR>>,
                                         rc_cc_ss = RCCCSS
                                        }, DataParts, []),
            Tpuds

    end.



encrypt_data(Key1, Key2, Data) ->
    IVec = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>,
    crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, Data).

swap_msisdn(MSISDN) when erlang:length(MSISDN) == 9 ->
    swap_msisdn("48"++MSISDN);

swap_msisdn(MSISDN) when erlang:length(MSISDN) == 11 ->
    Parts = ucp_utils:binary_split(
              erlang:list_to_binary(MSISDN),2),
    lists:flatten(
      [lists:reverse(erlang:binary_to_list(X)) || X <- Parts]
     ).


create_device_tlv(#device_tlv{source = SOURCE,
                              destination = DEST
                             }) ->
    TAG = <<16#02>>, %% HardCoded TAG
    LENGTH = size(TAG) + size(SOURCE) + size(DEST),
    << TAG/binary,
       LENGTH:8,
       SOURCE/binary,
       DEST/binary>>.


create_tp_address(#tp_address{ton_npi=TONNPI, address=ADDRESS}) ->
    TAG = <<16#06>>, %% HardCoded TAG
    LENGTH = size(TONNPI) + size(ADDRESS),
    << TAG/binary,
       LENGTH:8,
       TONNPI/binary,
       ADDRESS/binary >>.

create_tpud(#tpud{udhl = UDHL,
                  ieia =  IEIa,
                  iedla = IEDLa,
                  spi = SPI,
                  kic = KIC,
                  kid = KID,
                  tar = TAR,
                  cntr = CNTR,
                  pcntr = PCNTR,
                  rc_cc_ss = RC_CC_SS,
                  secured_data = Data
                 }) ->

    ?SYS_DEBUG("UDHL   ~p~n",[UDHL]),
    ?SYS_DEBUG("IEIa   ~p~n",[IEIa]),
    ?SYS_DEBUG("IEIDLa ~p~n",[IEDLa]),
    ?SYS_DEBUG("SPI    ~p~n",[SPI]),
    ?SYS_DEBUG("KIC    ~p~n",[KIC]),
    ?SYS_DEBUG("KID    ~p~n",[KID]),
    ?SYS_DEBUG("TAR    ~p~n",[TAR]),
    ?SYS_DEBUG("CNTR   ~p~n",[CNTR]),
    ?SYS_DEBUG("PCNTR  ~p~n",[PCNTR]),
    ?SYS_DEBUG("RCCCSS ~p~n",[RC_CC_SS]),
    ?SYS_DEBUG("DATA   ~p~n",[Data]),


    CHL = 21,
    CPL = CHL + size(Data) + 1, %% CHL is coded on two bytes
    [<<UDHL/binary,
      IEIa/binary,
      IEDLa/binary,
      CPL:16,
      CHL:8,
      SPI/binary,
      KIC/binary,
      KID/binary,
      TAR/binary,
      CNTR/binary,
      PCNTR/binary,
      RC_CC_SS/binary,
      Data/binary>>].

create_tpud_concatenated(_,[], Acc) ->
    Acc;

create_tpud_concatenated(#concatenated_tpud{
                                            ieia = IEIa, %% '00', indicating concatenated shortmessage
                                            ieidla = IEIDLa, %% 3
                                            ieida = <<Sec,Act,Tot>>,  %% refnum, sequence-num, total_messages 3 octets
                                            ieib = IEIb, %% 70
                                            ieidlb = IEIDLb, %% 00
                                            %% cpl = CPL,  %%  length od ieib do secured_data?
                                            %% chl = CHL, %% od spi do konca?
                                            spi = SPI,
                                            kic = KIC,
                                            kid = KID,
                                            tar = TAR,
                                            cntr = CNTR,
                                            pcntr = PCNTR,
                                            rc_cc_ss = RC_CC_SS
                                           }, [ActualPart|DataParts], Acc) ->
    ASec = Sec+1,
    AAct = Act+1,
    Tpdu = create_tpud_concatenated(#concatenated_tpud{
                                            ieia = IEIa, %% '00', indicating concatenated shortmessage
                                            ieidla = IEIDLa, %% 3
                                            ieida = <<ASec,AAct,Tot>>,  %% refnum, sequence-num, total_messages 3 octets
                                            ieib = IEIb, %% 70
                                            ieidlb = IEIDLb, %% 00
                                            spi = SPI,
                                            kic = KIC,
                                            kid = KID,
                                            tar = TAR,
                                            cntr = CNTR,
                                            pcntr = PCNTR,
                                            rc_cc_ss = RC_CC_SS,
                                            secured_data_part = ActualPart
                                           }),
    create_tpud_concatenated(#concatenated_tpud{
                                            ieia = IEIa, %% '00', indicating concatenated shortmessage
                                            ieidla = IEIDLa, %% 3
                                            ieida = <<ASec,AAct,Tot>>,  %% refnum, sequence-num, total_messages 3 octets
                                            ieib = IEIb, %% 70
                                            ieidlb = IEIDLb, %% 00
                                            spi = SPI,
                                            kic = KIC,
                                            kid = KID,
                                            tar = TAR,
                                            cntr = CNTR,
                                            pcntr = PCNTR,
                                            rc_cc_ss = RC_CC_SS
                                           }, DataParts, [Tpdu|Acc]).


create_tpud_concatenated(#concatenated_tpud{
                                            ieia = IEIa, %% '00', indicating concatenated shortmessage
                                            ieidla = IEIDLa, %% 3
                                            ieida = IEIDa,  %% refnum, sequence-num, total_messages 3 octets
                                            ieib = IEIb, %% 70
                                            ieidlb = IEIDLb, %% 00
                                            spi = SPI,
                                            kic = KIC,
                                            kid = KID,
                                            tar = TAR,
                                            cntr = CNTR,
                                            pcntr = PCNTR,
                                            rc_cc_ss = RC_CC_SS,
                                            secured_data_part = Data
                                           }) ->
    CHL = size(SPI) + size(KIC) + size(KID) +
        size(TAR) + size(CNTR) + size(PCNTR) + size(RC_CC_SS) + size(Data),
    CPL = CHL + 2,
    UDHL = size(IEIa) + size(IEIDLa) + size(IEIDa) + size(IEIb) + size(IEIDLb),
    UDL = UDHL + CPL + 2 + 1 + size(SPI) + size(KIC) + size(KID) +  size(TAR) + size(CNTR) + size(PCNTR) + size(RC_CC_SS) + size(Data),

    ?SYS_DEBUG("UDL    ~p~n",[UDL]),
    ?SYS_DEBUG("UDHL   ~p~n",[UDHL]),
    ?SYS_DEBUG("IEIa   ~p~n",[IEIa]),
    ?SYS_DEBUG("IEIDLa ~p~n",[IEIDLa]),
    ?SYS_DEBUG("IEIDa  ~p~n",[IEIDa]),
    ?SYS_DEBUG("IEIb   ~p~n",[IEIb]),
    ?SYS_DEBUG("IEIDlb ~p~n",[IEIDLb]),
    ?SYS_DEBUG("CPL    ~p~n",[CPL]),
    ?SYS_DEBUG("CHL    ~p~n",[CHL]),
    ?SYS_DEBUG("SPI    ~p~n",[SPI]),
    ?SYS_DEBUG("KIC    ~p~n",[KIC]),
    ?SYS_DEBUG("KID    ~p~n",[KID]),
    ?SYS_DEBUG("TAR    ~p~n",[TAR]),
    ?SYS_DEBUG("CNTR   ~p~n",[CNTR]),
    ?SYS_DEBUG("PCNTR  ~p~n",[PCNTR]),
    ?SYS_DEBUG("RCCCSS ~p~n",[RC_CC_SS]),
    ?SYS_DEBUG("DATA   ~p~n",[Data]),


    <<UDL:8,
      UDHL:8,
      IEIa/binary,
      IEIDLa/binary,
      IEIDa/binary,
      IEIb/binary,
      IEIDLb/binary,
      CPL:16,
      CHL:8,
      SPI/binary,
      KIC/binary,
      KID/binary,
      TAR/binary,
      CNTR/binary,
      PCNTR/binary,
      RC_CC_SS/binary,
      Data/binary
    >>.

create_tpdu(#tpdu{mti_mms_udhl_rp = MTI_MMS_UDHL_RP,
                  address_len = ADDRESS_LEN,
                  ton_npi = TON_NPI,
                  address_value = ADDRESS_VALUE,
                  tp_pid = TP_PID,
                  tp_dcs = TP_DCS,
                  tp_scts = TP_SCTS,
                  tp_ud = TP_UD
                 }) ->
    TAG = <<16#0b>>,
    TP_UDL = size(TP_UD),
    LENGTH = size(MTI_MMS_UDHL_RP) +
        size(ADDRESS_VALUE) + 2 + %% from TON_NPI and ADDRESS_LEN
        size(TP_PID) +
        size(TP_DCS) +
        size(TP_SCTS) +
        size(TP_UD) + 1, %% for TP_UDL
    << TAG/binary,
       LENGTH:8,
       MTI_MMS_UDHL_RP/binary,
       ADDRESS_LEN:8,
       TON_NPI/binary,
       ADDRESS_VALUE/binary,
       TP_PID/binary,
       TP_DCS/binary,
       TP_SCTS/binary,
       TP_UDL:8,
       TP_UD/binary >>.

create_apdu(#apdu{device_identity_tlv = DEVICE_IDENTITY_TLV,
                  address_tlv = ADDRESS_TLV,
                  sms_tpdu = SMS_TPDU
                 }) ->
    TAG = <<16#d1>>,
    LENGTH = size(DEVICE_IDENTITY_TLV)  +
        size(SMS_TPDU) +
        size(ADDRESS_TLV),
    << TAG/binary,
       LENGTH:8,
       DEVICE_IDENTITY_TLV/binary,
       ADDRESS_TLV/binary,
       SMS_TPDU/binary>>.


create_whole_command(Tpud) ->
    Data = <<16#AA, 16#AA, 16#AA>>,
    Tpud = create_tpud(Data),

    Address = swap_msisdn("501501501"),

    Device_tlv = create_device_tlv(#device_tlv{source = <<16#83>>, %% 83h is a source device (Network)
                                               destination = <<16#81>> %% Value—the destination device of the command is the UICC
                                              }),

    TpAddress = create_tp_address(#tp_address{ton_npi= <<16#98>>,
                                              address=Address}),

    Tpdu = create_tpdu(
             #tpdu{mti_mms_udhl_rp= <<16#e4>>,
                   address_len = size(Address)*2, %% number of octets
                   ton_npi = <<16#98>>,  %% NPI National numbering plan = 8 TON WTF ???
                   address_value = Address, %% This strange swapped format
                   tp_pid= <<16#7f>>, %% SIM data download
                   tp_dcs= <<16#16>>, %% WHAT THE FUCK???
                   tp_scts=erlang:list_to_binary(
                             [16#0B,16#09,16#05,16#16,16#54,16#25,16#04]), %% WTF??
                   tp_ud = Tpud
                  }),

    Apdu = create_apdu(
             #apdu{device_identity_tlv=Device_tlv,
                   address_tlv=TpAddress,
                   sms_tpdu=Tpdu}),
    Command = erlang:list_to_binary([16#a0, 16#c2, 16#00, 16#00]), %% download command (CLA a0, INS c2 P1 00 p2 00) iso/iec 7816-4
    Size = size(Apdu),
    << Command/binary, Size:8, Apdu/binary >>.



%%84/00236/O/51/798151973/3796//1//3/0539//////0710110923/0127/////4/528/004015160015150000004A4BD36156F208E7A7B1EDFCA7C22C297C544CC85DE796C7D8EA697509CE5EEC886D949A43C05D0A625BC85EC334B497B0341FB3C7746222//0//2//////01030270000201F6///56


%% 00 40 15 16 00 15 15 00 00 00 4A 4B D3 61 56 F2 08 E7 A7 B1 ED FC A7 C2 2C 29 7C 54 4C C8 5D E7 96 C7 D8 EA 69 75 09 CE 5E EC 88 6D 94 9A 43 C0 5D 0A 62 5B C8 5E C3 34 B4 97 B0 34 1F B3 C7 74 62 22

%% 00 40 CPL
%% 15 CHL
%% 16 00 SPI
%% 15 KIC
%% 15 KID
%% 00 00 00 TAR
%% 4A 4B D3 61 56 CNTR
%% F2 PCNTR
%% 08 E7 A7 B1 ED FC A7 C2 RC_CC_DS
%% 2C 29 7C 54 4C C8 5D E7 96 C7 D8 EA 69 75 09 CE 5E EC 88 6D 94 9A 43 C0 5D 0A 62 5B C8 5E C3 34 B4 97 B0 34 1F B3 C7 74 62 22

%% np moj numer z country codem
%%               wygladal by tak
%% 84 05 31 00 82 00
%% 48 50 13 00 28 00



%% 02 70 00 00 30 15 0E 19 25 25 00 00 00 01 0E 0A UNDERSTANDING.. .....
%% 8A 0E 1B D8 0C AB B2 C3 F3 90 3D 80 EF 57 9B AE
%% EC BE 69 41 A6 DC 0D 43 7D 55 3F E1 20 02 67 65
%% CF 49 7D EE 5D


%% 02 70 00 00 30 15 02 01 25 25 00 00 00 01 0E 0A  .p..0...%%......
%% 8A 0E 00 D8 0C AB B2 C3 F3 90 3D 80 EF 57 9B AE  ..Ø.«²Ãó=ïW®
%% EC BE 69 41 A6 DC 0D 43 7D 55 3F E1 20 02 67 65  ì¾iA¦Ü.C}U?á .ge
%% CF 49 7D EE 5D                                   ÏI}î]



%% 02 70 00 00 7E 15 06 0C 0C 44 41 52 00 00 00 00
%% 00 04 D8 0C AB B2 C3 F3 90 3D 30 96 44 D6 C1 71
%% DB 35 5F BE 16 AA 20 3A 2D 0D 62 AE B2 71 C9 A6
%% 64 BF 64 70 30 B6 E0 7E 03 42 6C FD B4 44 66 E4
%% AC F8 54 32 CC 06 E7 7E 48 94 5C 8A 17 D7 7C 02
%% A5 C5 8E C1 8A 11 3C 8F 93 AB BE 36 4F 71 12 AB
%% 07 A5 C4 41 5E F5 B9 51 DC EF EF 3E CA C9 58 B0
%% 5E 23 83 69 63 93 1B ED A1 C6 AE F9 9E 28 B9 FC
%% 15 8F
