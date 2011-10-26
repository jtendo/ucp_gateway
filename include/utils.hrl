-define(PRIV(Fname), filename:join([code:priv_dir(ucp_gateway), Fname])).

-define(PRIV_SUBDIR(Dirname),
    lists:append(filename:join([code:priv_dir(ucp_gateway), Dirname]), "/")).

-define(DUMPFILE, fun(Dirname, Suff) ->
        Dumpdir = ?PRIV_SUBDIR(Dirname),
        filelib:ensure_dir(Dumpdir),
        Ts = fs_utils:iso_8601_fmt(file_friendly, erlang:localtime()),
        Fname = lists:concat(["dump_", Suff, ".", Ts]),
        filename:join(Dumpdir, Fname)
end).
