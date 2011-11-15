-module(ucp_smspp).
-author('rafal.galczynski@jtendo.com').

-include("apdu.hrl").
-include("logger.hrl").
-export([
         create_tpud_message/4,
         parse_command_packet/1,
         test/1]).

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Function for creating tpud binary message
%% after GSM 03.48
%%
%% @spec create_tpud_message(SP::Record, TAR::Binary,
%%                           CNTR_VAL::integer(), Data::Binary) -> {data, Binary}
%% @end
%%--------------------------------------------------------------------
create_tpud_message(SP, TAR, CNTR_VAL, Data) when is_record(SP, sim_profile),
                                                  is_binary(TAR),
                                                  is_binary(Data),
                                                  is_integer(CNTR_VAL) ->

    KIC = SP#sim_profile.kic,
    KID = SP#sim_profile.kic,
    SPI = SP#sim_profile.spi,

    ConstPart = <<SPI/binary, KIC/binary, KID/binary, TAR/binary>>,

    {cc, {CC_TYPE, CC_SIZE}, cntr, IS_CNTR, enc, IS_ENC} = analyze_spi(SP#sim_profile.spi),

    CNTR = calculate_cntr(IS_CNTR, CNTR_VAL),
    ?SYS_DEBUG("KIC            ~p, ~p~n", [KIC, analyze_kic(KIC)]),
    ?SYS_DEBUG("KID            ~p~n", [KID]),
    ?SYS_DEBUG("SPI            ~p~n", [hex:to_hexstr(SPI)]),
    ?SYS_DEBUG("CNTR           ~p~n", [hex:to_hexstr(CNTR)]),
    case IS_ENC of
        noenc->
            PCNTR = <<0>>,
            RC_CC_DS = <<>>,
            ?SYS_DEBUG("PCNTR  ~p~n", [hex:to_hexstr(PCNTR)]),
            ?SYS_DEBUG("CC     ~p~n", [hex:to_hexstr(RC_CC_DS)]),

            CHL = size(ConstPart) + size(CNTR)  + size(RC_CC_DS) + size(PCNTR),
            CPL = size(ConstPart) + size(CNTR) + size(PCNTR) + size(<<CHL>>) + size(Data),
            ?SYS_DEBUG("CHL    ~p,~p~n", [CHL, hex:to_hexstr(CHL)]),
            ?SYS_DEBUG("CPL    ~p,~p~n", [CPL, hex:to_hexstr(CPL)]),

            DataToSend = <<CNTR/binary, PCNTR/binary, Data/binary>>,
            ?SYS_DEBUG("DATA   ~p~n", [hex:to_hexstr(DataToSend)]),
            {data, << CPL:16, CHL:8, ConstPart/binary, DataToSend/binary >>};
        enc ->
            SizeOfDataToCrypt = size(Data) + size(CNTR) + CC_SIZE + 1, %% +1 for PCNTR
            PCNTR = (8-(SizeOfDataToCrypt rem 8)),
            ?SYS_DEBUG("PCNTR  ~p~n", [hex:to_hexstr(PCNTR)]),

            CHL = size(ConstPart) + size(CNTR) + size(<<PCNTR>>) + CC_SIZE,
            CPL = size(ConstPart) + SizeOfDataToCrypt + PCNTR + size(<<CHL>>),
            ?SYS_DEBUG("CHL    ~p~n", [CHL]),
            ?SYS_DEBUG("CPL    ~p~n", [CPL]),

            ToCC_nopadding = <<CPL:16, CHL:8, ConstPart/binary, CNTR/binary, PCNTR:8, Data/binary, 0:(PCNTR*8)>>,
            ToCC = ucp_utils:pad_to(8,ToCC_nopadding),
            ?SYS_DEBUG("TOCC   ~p~n", [hex:to_hexstr(ToCC)]),

            RC_CC_DS = prepare_cc(CC_TYPE, SP, ToCC),
            ?SYS_DEBUG("CC     ~p~n", [hex:to_hexstr(RC_CC_DS)]),

            ToCrypt = <<CNTR/binary, PCNTR:8, RC_CC_DS/binary, Data/binary>>,
            DataToSend = crypt_data(analyze_kic(KIC), SP, ToCrypt),
            ?SYS_DEBUG("DATA   ~p~n", [hex:to_hexstr(DataToSend)]),
            {data, << CPL:16, CHL:8, ConstPart/binary, DataToSend/binary >>}
    end.


test(String) ->
    SP = get_sim_profile(),
    confetti:use(sim_profile),
    Conf = confetti:fetch(sim_profile),
    TAR = proplists:get_value(tar, Conf, <<>>),
    CNTR = 0,
    Data = erlang:list_to_binary(String),
    ?SYS_DEBUG("SP             ~p~n", [SP]),
    ?SYS_DEBUG("TAR            ~p~n", [hex:to_hexstr(TAR)]),
    ?SYS_DEBUG("CNTR           ~p~n", [hex:to_hexstr(CNTR)]),
    ?SYS_DEBUG("DATA           ~p~n", [Data]),
    create_tpud_message(SP, TAR, CNTR, Data).

get_sim_profile() ->
    confetti:use(sim_profile),
    Conf = confetti:fetch(sim_profile),
    KicKey1 = proplists:get_value(kic1, Conf, <<>>),
    %% SPIA =
    %%     ?SPI_NO_RC_CC_DS bor
    %%     ?SPI_NO_ENCRYPTION bor
    %%     ?SPI_COUNTER_PROCESS_IF_HIGHER_THEN_RE,
    %% SPIB =
    %%     ?SPI_POR_TO_SE bor
    %%     ?SPI_POR_NO_RC_CC_DS bor
    %%     ?SPI_POR_NOT_ENCRYPTED bor
    %%     ?SPI_POR_SMS_DELIVER_REPORT,

    SPIA =
        ?SPI_CC bor
        ?SPI_ENCRYPTION bor
        ?SPI_COUNTER_PROCESS_IF_HIGHER_THEN_RE,
    SPIB =
        ?SPI_POR_TO_SE bor
        ?SPI_POR_NO_RC_CC_DS bor
        ?SPI_POR_NOT_ENCRYPTED bor
        ?SPI_POR_SMS_DELIVER_REPORT,

    SPI = <<SPIA:8, SPIB:8>>,

    KicKeyIndex = proplists:get_value(kic_key_index, Conf, 0),
    KidKeyIndex = proplists:get_value(kid_key_index, Conf, 0),

    KIC = ?KIC_ALGORITHM_DES bor ?KIC_ALGORITHM_3DES2 bor KicKeyIndex,
    KID = ?KID_ALGORITHM_DES bor ?KID_ALGORITHM_3DES2 bor KidKeyIndex,

    KicKey1 = proplists:get_value(kic1, Conf, <<>>),
    KicKey2 = proplists:get_value(kic2, Conf, <<>>),

    KidKey1 = proplists:get_value(kid1, Conf, <<>>),
    KidKey2 = proplists:get_value(kid2, Conf, <<>>),

    SP = #sim_profile{
      spi=SPI,
      kic= <<KIC>>,
      kid= <<KID>>,
      kic_key1=KicKey1,
      kic_key2=KicKey2,
      kid_key1=KidKey1,
      kid_key2=KidKey2
     },
    SP.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function for calculating Cryptographic Checksum
%%
%% @spec calculate_cc(Key1::Binary, Key2::Binary, Data::Binary) -> Binary
%% @end
%%--------------------------------------------------------------------

calculate_cc(Key1, Key2, Data) ->
    [Block| Rest] = ucp_utils:binary_split(Data, 8),
    IVec = <<16#00,16#00,16#00,16#00,16#00,16#00,16#00,16#00>>,
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, IVec, Block),
    ?SYS_DEBUG("block          ~p~n",[hex:to_hexstr(Block)]),
    ?SYS_DEBUG("res            ~p~n",[hex:to_hexstr(Res)]),
    [ NextBlock | RestBlocks ] = Rest,
    calculate_cc(Key1, Key2, Res, NextBlock, RestBlocks).

calculate_cc(Key1, Key2, LastBlock, Block, []) ->
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, LastBlock, Block),
    ?SYS_DEBUG("res            ~p~n",[hex:to_hexstr(Res)]),
    Res;

calculate_cc(Key1, Key2, LastBlock, Block, Rest) ->
    Res =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, LastBlock, Block),
    [ NextBlock | RestBlocks ] = Rest,
    ?SYS_DEBUG("block          ~p~n",[hex:to_hexstr(Block)]),
    ?SYS_DEBUG("res            ~p~n",[hex:to_hexstr(Res)]),
    calculate_cc(Key1, Key2, Res, NextBlock, RestBlocks).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returs valid Counter binary
%%
%% @spec calculate_cntr(Counter_Type::Atom, Val::Binary) -> Binary
%% @end
%%--------------------------------------------------------------------

calculate_cntr(cntr, Val)->
    <<Val:40>>;
calculate_cntr(nocntr, _Val) ->
    <<>>.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns CryptographicChecsum/RedundancyCheck/DigitalSignature
%%
%% @spec prepare_cc(CC_Type::Atom, SP::Record, Data::Binary) -> Binary
%% @end
%%--------------------------------------------------------------------

prepare_cc(nocc, _SP, _Data) ->
    <<>>;
prepare_cc(rc, _SP, _Data) ->
    <<>>;
prepare_cc(cc, SP, Data) ->
    calculate_cc(
      SP#sim_profile.kid_key1,
      SP#sim_profile.kid_key2,
      Data);
prepare_cc(ds, _SP, _Data) ->
    <<>>.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns defined type of RC/CC/DS
%%
%% @spec analyze_cc(integer()) -> {Type::Atom, BitSize::integer()}
%% @end
%%--------------------------------------------------------------------

analyze_cc(2#00) ->
    {nocc, 0};
analyze_cc(2#01) ->
    {rc, 8};
analyze_cc(2#10) ->
    {cc, 8};
analyze_cc(2#11) ->
    {ds, 24}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns defined type of counter
%%
%% @spec analyze_counter(integer()) -> Type::Atom
%% @end
%%--------------------------------------------------------------------

analyze_cntr(2#00) ->
    nocntr;
analyze_cntr(_) ->
    cntr.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns definition of encryption
%%
%% @spec analyze_enc(integer()) -> Type::Atom
%% @end
%%--------------------------------------------------------------------

analyze_enc(2#00) ->
    noenc;
analyze_enc(2#01) ->
    enc.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns definition of RC/CC/DS, encryption, and counter
%%
%% @spec analyze_enc(SPI::Binary) -> {cc, {Atom, integer()},
%%                                    cntr, Atom,
%%                                    enc, Atom}
%% @end
%%--------------------------------------------------------------------

analyze_spi(<<0:3, CNTR:2, ENC:1, CC:2, _:8>>) ->
    {cc, analyze_cc(CC), cntr, analyze_cntr(CNTR), enc, analyze_enc(ENC)}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns defined crypto algorithm in KIC field
%%
%% @spec analyze_kic(KIC::Binary) -> Algo::Atom
%% @end
%%--------------------------------------------------------------------

analyze_kic(<<_KeyIdx:4, Type:2, _Inf:2>>) ->
    case Type of
        2#00 ->
            des_cbc;
        2#01 ->
            tripledes2key;
        2#10 ->
            tripledes3key;
        2#11 ->
            reserved
    end.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns crypted data using given algo
%%
%% @spec crypt_data(algo::Atom, SP::Record, Data::Binary) -> Binary
%% @end
%%--------------------------------------------------------------------

crypt_data(tripledes2key, SP, Data) ->
    Key1 = SP#sim_profile.kic_key1,
    Key2 = SP#sim_profile.kic_key2,
    crypto:des3_cbc_encrypt(Key1, Key2, Key1, ?ZERO_IV, ucp_utils:pad_to(8,Data));

crypt_data(tripledes3key, SP, Data) ->
    Key1 = SP#sim_profile.kic_key1,
    Key2 = SP#sim_profile.kic_key2,
    Key3 = SP#sim_profile.kic_key3,
    crypto:des3_cbc_encrypt(Key1, Key2, Key3, ?ZERO_IV, ucp_utils:pad_to(8,Data));

crypt_data(des_cbc, SP, Data) ->
    Key1 = SP#sim_profile.kic_key1,
    crypto:des_cbc_encrypt(Key1, ?ZERO_IV, ucp_utils:pad_to(8,Data)).


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function parse 03.48 message, returns CNTR and DATA
%%
%% @spec parse_command_packet(Packet::Binary) ->
%%                           {cntr, CNTR::Binary, data, Data::Binary}
%% @end
%%--------------------------------------------------------------------

parse_command_packet(Packet) when is_list(Packet)->
    parse_command_packet(hex:hexstr_to_bin(Packet));

parse_command_packet(Packet) when is_binary(Packet)->
    <<_CPI:8, _CPL:8, _CHL:8, _SPI:16, _KIC:8, _KID:8, _TAR:24, CNTR:40, _PCNTR:8, Data/binary>> = Packet,
    {cntr, CNTR, data, Data}.


