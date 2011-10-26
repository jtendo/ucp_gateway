-define(SYS_DEBUG(Format, Args), lager:debug(Format, Args)).
-define(SYS_INFO(Format, Args), lager:info(Format, Args)).
-define(SYS_WARN(Format, Args), lager:warning(Format, Args)).
-define(SYS_ERROR(Format, Args), lager:error(Format, Args)).
-define(SYS_FATAL(Format, Args), lager:critical(Format, Args)).

