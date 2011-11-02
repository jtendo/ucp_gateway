-module(ucp_smspp).
-author('rafal.galczynski@jtendo.com').

-include("../include/apdu.hrl").
-include("../include/logger.hrl").
-compile([export_all]).
-compile([debug_info]).
-define(CHUNK_SIZE, 113).

t() ->

    %% Data = <<16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>,
    %% Data = <<16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61,
    %%          16#6D, 16#61, 16#72, 16#63, 16#65, 16#6C, 16#20, 16#69, 16#20, 16#77, 16#69, 16#65, 16#72, 16#61
    %%        >>,
    Data = erlang:list_to_binary("JTENDO JTENDO"),
    TAR = <<16#52, 16#41, 16#44>>, %% Toolkit Application Reference (TAR): 3 octets.

    SPIA =
        ?SPI_CC bor
        ?SPI_ENCRYPTION bor
        ?SPI_COUNTER_AVAILABLE_NOT_CHECKED,
    SPIB =
        ?SPI_POR_TO_SE bor
        ?SPI_POR_NO_RC_CC_DS bor
        ?SPI_POR_NOT_ENCRYPTED bor
        ?SPI_POR_SMS_DELIVER_REPORT,

    SPI = <<SPIA:8, SPIB:8>>,
    KIC = ?KIC_ALGORITHM_KNOWN bor ?KIC_ALGORITHM_3DES2 bor 2#100000, %% key id
    KID = ?KID_ALGORITHM_KNOWN bor ?KID_ALGORITHM_3DES2 bor 2#101000, %% key id

    KicKey1 = <<16#30, 16#42, 16#30, 16#42, 16#30, 16#44, 16#30, 16#44>>,
    KicKey2 = <<16#30, 16#45, 16#30, 16#45, 16#30, 16#46, 16#30, 16#46>>,

    KidKey1 = <<16#01, 16#23, 16#45, 16#67, 16#89, 16#AB, 16#CD, 16#EF>>,
    KidKey2 = <<16#10, 16#02, 16#76, 16#FE, 16#DC, 16#BA, 16#01, 16#23>>,

    CardProfile = #card_profile{
      spi=SPI,
      kic= <<KIC>>,
      kid= <<KID>>,
      kic_key1=KicKey1,
      kic_key2=KicKey2,
      kid_key1=KidKey1,
      kid_key2=KidKey2
     },

    [X] = smspp:create_tpud_message(CardProfile, TAR, Data),
    binpp:pprint(X),
    C = create_whole_command(X),
    binpp:pprint(C).


create_tpud_message(CProf, TAR, Data) when is_binary(Data)->
    {ok, data, TPUD, rcccds, RC_CC_DS, pcntr, PCNTR} = create_tpud(CProf, TAR, Data),
    case size(TPUD) =< ?CHUNK_SIZE of
        true ->
            [TPUD];
        false ->
            DataParts = ucp_utils:binary_split(TPUD,?CHUNK_SIZE),
            Sec = 0,
            Act = 0,
            Tot = length(DataParts),
            CNTR = <<16#00, 16#00, 16#00, 16#00, 16#00>>, %% (Counter): 5 octets, counter management
            Tpuds = create_tpud_concatenated(
                      #concatenated_tpud{ieia = <<00>>,
                                         ieidla = <<03>>,
                                         ieida = <<Sec,Act,Tot>>,
                                         ieidlb = <<00>>,
                                         ieib = <<70>>,
                                         spi = CProf#card_profile.spi,
                                         kic = CProf#card_profile.kic,
                                         kid = CProf#card_profile.kid,
                                         tar = TAR,
                                         cntr = CNTR,
                                         pcntr = <<PCNTR>>,
                                         rc_cc_ds = RC_CC_DS
                                        }, DataParts, []),
            Tpuds

    end.


calculate_mac(Key1, Key2, Data) ->
    [Block| Rest] = ucp_utils:binary_split(Data, 8),
    IVec = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>,
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, Block),
    ?SYS_DEBUG("block                  ~p~n",[hex:bin_to_hexstr(Block)]),
    ?SYS_DEBUG("res                    ~p~n",[hex:bin_to_hexstr(Res)]),
    [ NextBlock | RestBlocks ] = Rest,
    calculate_mac(Key1, Key2, Res, NextBlock, RestBlocks).

calculate_mac(Key1, Key2, LastBlock, Block, []) ->
    IVec = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>,
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, LastBlock, Block),
    Mac = crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, Res),
    ?SYS_DEBUG("RES                  ~p~n",[hex:bin_to_hexstr(IVec)]),
    ?SYS_DEBUG("CC                  ~p~n",[hex:bin_to_hexstr(Mac)]),
    Mac;

calculate_mac(Key1, Key2, LastBlock, Block, Rest) ->
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, LastBlock, Block),
    [ NextBlock | RestBlocks ] = Rest,
    ?SYS_DEBUG("block                  ~p~n",[hex:bin_to_hexstr(Block)]),
    ?SYS_DEBUG("res                    ~p~n",[hex:bin_to_hexstr(Res)]),
    calculate_mac(Key1, Key2, Res, NextBlock, RestBlocks).

binary_xor(B1, B2) ->
    erlang:list_to_binary(
      lists:zipwith(
        fun(X, Y) ->
                X bxor Y
        end,
        erlang:binary_to_list(B1),
        erlang:binary_to_list(B2)
       )
     ).


des3_encrypt_data(Key1, Key2, Data) ->
    IVec = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>,
    crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, ucp_utils:pad_to(8,Data)).

des3_encrypt_data(Key1, Key2, Data, IVec) ->
    crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, ucp_utils:pad_to(8,Data)).


des_encrypt_data(Key, IVec, Data) ->
    crypto:des_cbc_encrypt(Key, IVec, ucp_utils:pad_to(8,Data)).

des_decrypt_data(Key, IVec, Data) ->
    crypto:des_cbc_decrypt(Key, IVec, ucp_utils:pad_to(8,Data)).

create_tpud(CProf, TAR, Data) ->
    CNTR = <<16#00, 16#00, 16#00, 16#00, 16#00>>, %% (Counter): 5 octets, counter management
    KIC = CProf#card_profile.kic,
    KID = CProf#card_profile.kic,
    <<SPIA, SPIB>> = CProf#card_profile.spi,
    ConstPart = <<SPIA:8, SPIB:8, KIC/binary, KID/binary, TAR/binary>>,
    SizeOfDataToCrypt = size(Data) + size_CNTR(SPIA) + size_PCNTR(SPIA) + size_RC_CC_DS(SPIA),
    PCNTR = (8-(SizeOfDataToCrypt rem 8)),

    CHL = size(ConstPart) + size_CNTR(SPIA) + size_PCNTR(SPIA) + size_RC_CC_DS(SPIA),
    CPL = size(ConstPart) + SizeOfDataToCrypt + PCNTR + 1,

    ToCC_nopadding = <<CPL:16, CHL:8, ConstPart/binary, CNTR/binary, PCNTR:8, Data/binary>>,
    ToCC = ucp_utils:pad_to(8,ToCC_nopadding),

    RC_CC_DS = calculate_mac(
                 CProf#card_profile.kid_key1,
                 CProf#card_profile.kid_key2,
                 ToCC),

    ToCrypt = <<CNTR/binary, PCNTR:8, RC_CC_DS/binary, Data/binary>>,

    SecureData = des3_encrypt_data(
                   CProf#card_profile.kic_key1,
                   CProf#card_profile.kic_key2,
                   ToCrypt),

    ?SYS_DEBUG("CPL                  ~p, ~p~n", [hex:int_to_hexstr(CPL), CPL]),
    ?SYS_DEBUG("CHL                  ~p, ~p~n", [hex:int_to_hexstr(CHL), CHL]),
    ?SYS_DEBUG("SPI                  ~p~n",     [hex:bin_to_hexstr(CProf#card_profile.spi)]),
    ?SYS_DEBUG("KIC                  ~p~n",     [hex:bin_to_hexstr(KIC)]),
    ?SYS_DEBUG("KID                  ~p~n",     [hex:bin_to_hexstr(KID)]),
    ?SYS_DEBUG("TAR                  ~p~n",     [hex:bin_to_hexstr(TAR)]),
    ?SYS_DEBUG("CNTR                 ~p~n",     [hex:bin_to_hexstr(CNTR)]),
    ?SYS_DEBUG("PCNTR                ~p~n",     [hex:int_to_hexstr(PCNTR)]),
    ?SYS_DEBUG("TO-CC                ~p~n",     [hex:bin_to_hexstr(ToCC)]),
    ?SYS_DEBUG("RCCCDS               ~p~n",     [hex:bin_to_hexstr(RC_CC_DS)]),
    ?SYS_DEBUG("DATA                 ~p~n",     [hex:bin_to_hexstr(Data)]),
    ?SYS_DEBUG("SDATA                ~p~n",     [hex:bin_to_hexstr(SecureData)]),

    {ok,
     data, <<CPL:16, CHL:8, ConstPart/binary, SecureData/binary>>,
     rcccds, RC_CC_DS,
     pcntr, PCNTR}.


size_PCNTR(0) ->
    0;
size_PCNTR(4) ->
    1;
size_PCNTR(_) ->
    1.

size_RC_CC_DS(0) ->
    0;
size_RC_CC_DS(1) ->
    4;
size_RC_CC_DS(2) ->
    8;
size_RC_CC_DS(3) ->
    8;
size_RC_CC_DS(4) ->
    0;
size_RC_CC_DS(_) ->
    8.

size_CNTR(0) ->
    0;
size_CNTR(_) ->
    5.


create_tpud_concatenated(_,[], Acc) ->
    Acc;

create_tpud_concatenated(#concatenated_tpud{ieia = IEIa, ieidla = IEIDLa, ieida = <<Sec,Act,Tot>>,
                                            ieib = IEIb, ieidlb = IEIDLb, spi = SPI, kic = KIC,
                                            kid = KID, tar = TAR, cntr = CNTR, pcntr = PCNTR,
                                            rc_cc_ds = RC_CC_SS},
                         [ActualPart|DataParts], Acc) ->
    ASec = Sec+1,
    AAct = Act+1,
    Tpdu = create_tpud_concatenated(
             #concatenated_tpud{ieia = IEIa, ieidla = IEIDLa, ieida = <<ASec,AAct,Tot>>,
                                ieib = IEIb, ieidlb = IEIDLb, spi = SPI, kic = KIC,
                                kid = KID, tar = TAR, cntr = CNTR, pcntr = PCNTR,
                                rc_cc_ds = RC_CC_SS,
                                secured_data_part = ActualPart}),
    create_tpud_concatenated(
      #concatenated_tpud{ieia = IEIa, ieidla = IEIDLa, ieida = <<ASec,AAct,Tot>>,
                         ieib = IEIb, ieidlb = IEIDLb, spi = SPI, kic = KIC,
                         kid = KID, tar = TAR, cntr = CNTR, pcntr = PCNTR,
                         rc_cc_ds = RC_CC_SS
                        }, DataParts, [Tpdu|Acc]).


create_tpud_concatenated(#concatenated_tpud{ieia = IEIa, ieidla = IEIDLa, ieida = IEIDa, ieib = IEIb, %% 70
                                            ieidlb = IEIDLb, spi = SPI, kic = KIC, kid = KID, tar = TAR,
                                            cntr = CNTR, pcntr = PCNTR, rc_cc_ds = RC_CC_SS,
                                            secured_data_part = Data
                                           }) ->

    CHL = size(SPI) + size(KIC) + size(KID) +
        size(TAR) + size(CNTR) + size(PCNTR) +
        size(RC_CC_SS) +
        size(Data),
    CPL = CHL + 2,
    UDHL = size(IEIa) + size(IEIDLa) + size(IEIDa) + size(IEIb) + size(IEIDLb),
    UDL = UDHL + CPL + 2 + 1 + size(SPI) + size(KIC) +
        size(KID) +  size(TAR) + size(CNTR) + size(PCNTR) +
        size(RC_CC_SS) +
        size(Data),


    ?SYS_DEBUG("UDL                  ~p~n",[hex:int_to_hexstr(UDL)]),
    ?SYS_DEBUG("UDHL                 ~p~n",[hex:int_to_hexstr(UDHL)]),
    ?SYS_DEBUG("IEIa                 ~p~n",[hex:bin_to_hexstr(IEIa)]),
    ?SYS_DEBUG("IEIDLa               ~p~n",[hex:bin_to_hexstr(IEIDLa)]),
    ?SYS_DEBUG("IEIDa                ~p~n",[hex:bin_to_hexstr(IEIDa)]),
    ?SYS_DEBUG("IEIb                 ~p~n",[hex:bin_to_hexstr(IEIb)]),
    ?SYS_DEBUG("IEIDlb               ~p~n",[hex:bin_to_hexstr(IEIDLb)]),
    ?SYS_DEBUG("CPL                  ~p~n",[hex:int_to_hexstr(CPL)]),
    ?SYS_DEBUG("CHL                  ~p~n",[hex:int_to_hexstr(CHL)]),
    ?SYS_DEBUG("SPI                  ~p~n",[hex:bin_to_hexstr(SPI)]),
    ?SYS_DEBUG("KIC                  ~p~n",[hex:bin_to_hexstr(KIC)]),
    ?SYS_DEBUG("KID                  ~p~n",[hex:bin_to_hexstr(KID)]),
    ?SYS_DEBUG("TAR                  ~p~n",[hex:bin_to_hexstr(TAR)]),
    ?SYS_DEBUG("CNTR                 ~p~n",[hex:bin_to_hexstr(CNTR)]),
    ?SYS_DEBUG("PCNTR                ~p~n",[hex:bin_to_hexstr(PCNTR)]),
    ?SYS_DEBUG("RCCCSS               ~p~n",[hex:bin_to_hexstr(RC_CC_SS)]),
    ?SYS_DEBUG("DATA                 ~p~n",[hex:bin_to_hexstr(Data)]),


    <<UDL:8, UDHL:8, IEIa/binary, IEIDLa/binary, IEIDa/binary, IEIb/binary, IEIDLb/binary,
      CPL:16, CHL:8, SPI/binary, KIC/binary, KID/binary, TAR/binary, CNTR/binary,
      PCNTR/binary, RC_CC_SS/binary, Data/binary >>.



swap_msisdn(MSISDN) when erlang:length(MSISDN) == 9 ->
    swap_msisdn("48"++MSISDN);

swap_msisdn(MSISDN) when erlang:length(MSISDN) == 11 ->
    Parts = ucp_utils:binary_split(
              erlang:list_to_binary(MSISDN),2),
    lists:flatten(
      [lists:reverse(erlang:binary_to_list(X)) || X <- Parts]
     );

swap_msisdn(MSISDN) ->
    MSISDN.

create_device_tlv(#device_tlv{source = SOURCE,
                              destination = DEST
                             }) ->
    TAG = <<16#02>>, %% HardCoded TAG
    LENGTH = size(SOURCE) + size(DEST),

    ?SYS_DEBUG("DEVICE TAG           ~p~n",     [hex:bin_to_hexstr(TAG)]),
    ?SYS_DEBUG("DEVICE LEN           ~p~n",     [hex:int_to_hexstr(LENGTH)]),
    ?SYS_DEBUG("DEVICE SRC           ~p~n",     [hex:bin_to_hexstr(SOURCE)]),
    ?SYS_DEBUG("DEVICE DST           ~p~n",     [hex:bin_to_hexstr(DEST)]),
    << TAG/binary,
       LENGTH:8,
       SOURCE/binary,
       DEST/binary>>.

create_tp_address(#tp_address{ton_npi=TONNPI, address=ADDRESS}) ->
    TAG = <<16#06>>, %% HardCoded TAG
    LENGTH = size(TONNPI) + size(ADDRESS),

    ?SYS_DEBUG("ADDRESS TAG          ~p~n",     [hex:bin_to_hexstr(TAG)]),
    ?SYS_DEBUG("ADDRESS LEN          ~p~n",     [hex:int_to_hexstr(LENGTH)]),
    ?SYS_DEBUG("ADDRESS TON/NPI      ~p~n",     [hex:bin_to_hexstr(TONNPI)]),
    ?SYS_DEBUG("ADDRESS              ~p~n",     [hex:bin_to_hexstr(ADDRESS)]),

    << TAG/binary,
       LENGTH:8,
       TONNPI/binary,
       ADDRESS/binary >>.

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

    ?SYS_DEBUG("TPDU TAG             ~p~n",     [hex:bin_to_hexstr(TAG)]),
    ?SYS_DEBUG("TPDU LEN             ~p~n",     [hex:int_to_hexstr(LENGTH)]),
    ?SYS_DEBUG("TPDU MTI_MMS_UDHL_RP ~p~n",     [hex:bin_to_hexstr(MTI_MMS_UDHL_RP)]),
    ?SYS_DEBUG("TPDU ADDRESS LEN     ~p~n",     [hex:int_to_hexstr(ADDRESS_LEN)]),
    ?SYS_DEBUG("TPDU TON/NPI         ~p~n",     [hex:bin_to_hexstr(TON_NPI)]),
    ?SYS_DEBUG("TPDU ADDRESS_VALUE   ~p~n",     [hex:bin_to_hexstr(ADDRESS_VALUE)]),
    ?SYS_DEBUG("TPDU TP_PID          ~p~n",     [hex:bin_to_hexstr(TP_PID)]),
    ?SYS_DEBUG("TPDU TP_DCS          ~p~n",     [hex:bin_to_hexstr(TP_DCS)]),
    ?SYS_DEBUG("TPDU TP_SCTS         ~p~n",     [hex:bin_to_hexstr(TP_SCTS)]),
    ?SYS_DEBUG("TPDU TP_UDL          ~p~n",     [hex:int_to_hexstr(TP_UDL)]),
    ?SYS_DEBUG("TPDU TP_UD           ~p~n",     [hex:bin_to_hexstr(TP_UD)]),

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
    ?SYS_DEBUG("APDU TAG             ~p~n",     [hex:bin_to_hexstr(TAG)]),
    ?SYS_DEBUG("APDU LEN             ~p~n",     [hex:int_to_hexstr(LENGTH)]),
    ?SYS_DEBUG("APDU DEVICE_IDENTITY ~p~n",     [hex:bin_to_hexstr(DEVICE_IDENTITY_TLV)]),
    ?SYS_DEBUG("APDU ADDRESS         ~p~n",     [hex:bin_to_hexstr(ADDRESS_TLV)]),
    ?SYS_DEBUG("APDU TPDU            ~p~n",     [hex:bin_to_hexstr(SMS_TPDU)]),

    << TAG/binary,
       LENGTH:8,
       DEVICE_IDENTITY_TLV/binary,
       ADDRESS_TLV/binary,
       SMS_TPDU/binary>>.


create_whole_command(Tpud) ->

    %% Address = swap_msisdn("3311111111"),


    %% AddressBin = erlang:list_to_binary(Address),
    AddressBin = <<51,17,17,17,17>>,

    Tpdu = create_tpdu(
             #tpdu{mti_mms_udhl_rp= <<16#E4>>,
                   address_len = size(AddressBin)*2, %% number of octets
                   ton_npi = <<16#98>>,  %% NPI National numbering plan = 8 TON WTF ???
                   address_value = AddressBin, %% This strange swapped format
                   tp_pid = <<16#7f>>, %% SIM data download
                   tp_dcs = <<16#16>>, %% WHAT THE FUCK???
                   tp_scts = <<16#0B, 16#09, 16#27, 16#14, 16#33, 16#15, 16#04>>, %% ServiceCenter TimeStamp
                   tp_ud = <<16#02, 16#70, 16#00, Tpud/binary>>
                  }),


    Device_tlv = create_device_tlv(
                   #device_tlv{source = <<16#83>>, %% 83h is a source device (Network)
                               destination = <<16#81>> %% Value—the destination device of the command is the UICC
                              }),

    TpAddress = create_tp_address(
                  #tp_address{ton_npi= <<16#98>>,
                              address= AddressBin}),


    Apdu = create_apdu(
             #apdu{device_identity_tlv=Device_tlv,
                   address_tlv=TpAddress,
                   sms_tpdu=Tpdu}),

    Command = <<16#a0, 16#c2, 16#00, 16#00>>, %% download command (CLA a0, INS c2 P1 00 p2 00) iso/iec 7816-4
    Size = size(Apdu),
    << Command/binary, Size:8, Apdu/binary >>.



%% gem
%% 00 38 15 0E 01 24 24 52 41 44 60 D9 2F 04 87 6C
%% CD A2 A4 F6 44 44 E2 D8 6B CD A2 F7 A5 85 76 61
%% 62 09 60 4E C6 28 F2 11 F5 4D 9F A5 0F E5 A4 8C
%% F9 C0 CF 7F 48 1C 2C 34 AB DD


%% ja
%% 00 38 15 0E 01 24 24 52 41 44 A7 FD AA ED 54 0C
%% A0 E4 88 BE 78 5C 39 5C 53 10 D2 3E 24 6A F9 34
%% 02 BA B4 96 62 4D 16 06 CA 18 F9 F3 78 C1 55 8C
%% 15 32 D4 FA 46 FB 7F F3 8A 56
