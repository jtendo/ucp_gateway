-define(CFG, fun(Key,ConfFile,Default) ->
                     Terms = confetti:fetch(ConfFile),
                     proplists:get_value(Key, Terms, Default)
    end).
