-module(ucp_smspp).
-author('rafal.galczynski@jtendo.com').

-include("0348packet.hrl").
-include("logger.hrl").
-include("utils.hrl").

-export([
         create_tpud/4,
         create_tpud/2,
         parse_0348packet/1,
         test/1]).

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Function for creating tpud command packet
%% after GSM 03.48
%%
%% @spec create_tpud_message(SP::Record, TAR::Binary,
%%                           CNTR_VAL::integer(), Data::Binary) -> {data, Binary}
%% @end
%%--------------------------------------------------------------------
create_tpud(CNTR_VAL, Data) when is_binary(Data),
                                 is_integer(CNTR_VAL) ->
    SP = get_sim_profile(),
    TAR = ?CFG(tar, sim_profile_conf, <<>>),
    create_tpud(SP, TAR, CNTR_VAL, Data).

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Function for creating tpud command packet
%% after GSM 03.48
%%
%% @spec create_tpud_message(SP::Record, TAR::Binary,
%%                           CNTR_VAL::integer(), Data::Binary) -> {data, Binary}
%% @end
%%--------------------------------------------------------------------
create_tpud(SP, TAR, CNTR_VAL, Data) when is_record(SP, sim_profile),
                                          is_binary(TAR),
                                          is_binary(Data),
                                          is_integer(CNTR_VAL) ->

    KIC = SP#sim_profile.kic,
    KID = SP#sim_profile.kid,
    SPI = SP#sim_profile.spi,

    ConstPart = <<SPI/binary, KIC/binary, KID/binary, TAR/binary>>,

    {cc, {CC_TYPE, CC_SIZE}, cntr, IS_CNTR, enc, IS_ENC} = analyze_spi(SP#sim_profile.spi),

    CNTR = calculate_cntr(IS_CNTR, CNTR_VAL),
    ?SYS_DEBUG("KIC           ~p, ~p~n", [KIC, analyze_kic(KIC)]),
    ?SYS_DEBUG("KID           ~p, ~p~n", [KID, analyze_kic(KID)]),
    ?SYS_DEBUG("SPI           ~p, ~p~n", [hex:to_hexstr(SPI), analyze_spi(SPI)]),
    ?SYS_DEBUG("CNTR          ~p~n", [hex:to_hexstr(CNTR)]),
    case IS_ENC of
        noenc->
            PCNTR = <<0>>,
            RC_CC_DS = <<>>,
            ?SYS_DEBUG("PCNTR         ~p~n", [hex:to_hexstr(PCNTR)]),
            ?SYS_DEBUG("CC            ~p~n", [hex:to_hexstr(RC_CC_DS)]),

            CHL = size(ConstPart) + size(CNTR)  + size(RC_CC_DS) + size(PCNTR),
            CPL = size(ConstPart) + size(CNTR) + size(PCNTR) + size(<<CHL>>) + size(Data),
            ?SYS_DEBUG("CHL           ~p,~p~n", [CHL, hex:to_hexstr(CHL)]),
            ?SYS_DEBUG("CPL           ~p,~p~n", [CPL, hex:to_hexstr(CPL)]),

            DataToSend = <<CNTR/binary, PCNTR/binary, Data/binary>>,
            ?SYS_DEBUG("DATA          ~p~n", [hex:to_hexstr(DataToSend)]),
            {data, << CPL:16, CHL:8, ConstPart/binary, DataToSend/binary >>};
        enc ->
            SizeOfDataToCrypt = size(Data) + size(CNTR) + CC_SIZE + 1, %% +1 for PCNTR

            PCNTR = prepare_pcntr(SizeOfDataToCrypt),
            ?SYS_DEBUG("PCNTR         ~p,~p~n", [PCNTR, hex:to_hexstr(PCNTR)]),

            CHL = size(ConstPart) + size(CNTR) + size(<<PCNTR>>) + CC_SIZE,
            CPL = size(ConstPart) + SizeOfDataToCrypt + PCNTR + size(<<CHL>>),
            ?SYS_DEBUG("CHL           ~p,~p~n", [CHL, hex:to_hexstr(CHL)]),
            ?SYS_DEBUG("CPL           ~p,~p~n", [CPL, hex:to_hexstr(CPL)]),

            ToCC_nopadding = <<CPL:16, CHL:8, ConstPart/binary, CNTR/binary, PCNTR:8, Data/binary, 0:(PCNTR*8)>>,
            ToCC = ucp_utils:pad_to(8,ToCC_nopadding),
            RC_CC_DS = prepare_cc(CC_TYPE, SP, ToCC),
            ?SYS_DEBUG("CC            ~p~n", [hex:to_hexstr(RC_CC_DS)]),

            ToCrypt = <<CNTR/binary, PCNTR:8, RC_CC_DS/binary, Data/binary>>,
            DataToSend = crypt_data(analyze_kic(KIC), SP, ToCrypt),
            ?SYS_DEBUG("DATA          ~p~n", [hex:to_hexstr(DataToSend)]),
            {data, << CPL:16, CHL:8, ConstPart/binary, DataToSend/binary >>}
    end.


test(String) ->
    CNTR = 0,
    Data = erlang:list_to_binary(String),
    create_tpud(CNTR, Data).

get_sim_profile() ->
    confetti:use(sim_profile_conf, [
                               {location, {"sim_profile.conf", "conf"}},
                               {subscribe, false}
                              ]),

    SPIA = ?CFG(spia, sim_profile_conf, 16#16),
    SPIB = ?CFG(spib, sim_profile_conf, 16#01),

    SPI = <<SPIA:8, SPIB:8>>,
    KIC = ?CFG(kic, sim_profile_conf, 0),
    KID = ?CFG(kid, sim_profile_conf, 0),

    KicKey = ?CFG(kickey, sim_profile_conf, 0),
    KidKey = ?CFG(kidkey, sim_profile_conf, 0),

    SP = #sim_profile{
      spi=SPI,
      kic= <<KIC>>,
      kid= <<KID>>,
      kickey=KicKey,
      kidkey=KidKey
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
    Bin =  crypto:des3_cbc_encrypt(Key1, Key2, Key1, ?ZERO_IV, Data),
    erlang:binary_part(Bin, {byte_size(Bin), -8}).

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
%% Function returns Padding Counter
%%
%% @spec prepare_cntr(SizeDataToCrypt::integer()) -> integer()
%% @end
%%--------------------------------------------------------------------

prepare_pcntr(SizeDataToCrypt) ->
    case SizeDataToCrypt rem 8 of
        0 ->
            0;
        _ ->
            8-(SizeDataToCrypt rem 8)
    end.

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
    KidKey = hex:hexstr_to_bin(SP#sim_profile.kidkey),
    [Key1, Key2] = ucp_utils:binary_split(KidKey, 8),
    calculate_cc(
      Key1,
      Key2,
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
%% Function returns defined crypto algorithm in KID field
%%
%% @spec analyze_kid(KIC::Binary) -> Algo::Atom
%% @end
%%--------------------------------------------------------------------

analyze_kid(KID) ->
    analyze_kic(KID).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Function returns crypted data using given algo
%%
%% @spec crypt_data(algo::Atom, SP::Record, Data::Binary) -> Binary
%% @end
%%--------------------------------------------------------------------

crypt_data(tripledes2key, SP, Data) ->
    KicKey = hex:hexstr_to_bin(SP#sim_profile.kickey),
    [Key1, Key2] = ucp_utils:binary_split(KicKey, 8),
    crypto:des3_cbc_encrypt(Key1, Key2, Key1, ?ZERO_IV, ucp_utils:pad_to(8,Data));

crypt_data(tripledes3key, SP, Data) ->
    KicKey = hex:hexstr_to_bin(SP#sim_profile.kickey),
    [Key1, Key2, Key3] = ucp_utils:binary_split(KicKey, 8),
    crypto:des3_cbc_encrypt(Key1, Key2, Key3, ?ZERO_IV, ucp_utils:pad_to(8,Data));

crypt_data(des_cbc, SP, Data) ->
    Key1 = SP#sim_profile.kickey,
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

parse_0348packet(Packet) when is_list(Packet)->
    parse_0348packet(hex:hexstr_to_bin(Packet));

parse_0348packet(Packet) when is_binary(Packet)->
    <<_CPI:8, _CPL:8, _CHL:8, _SPI:16, _KIC:8, _KID:8, _TAR:24, CNTR:40, _PCNTR:8, Data/binary>> = Packet,
    {cntr, CNTR, data, Data}.


