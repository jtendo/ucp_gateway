REBAR=`which rebar || echo ./rebar`

.PHONY: test deps

all: deps compile

deps:
	@$(REBAR) get-deps

compile:
	@$(REBAR) compile

test:
	@$(REBAR) skip_deps=true eunit

clean:
	@$(REBAR) clean
	-rm -rf deps ebin doc/* .eunit

run: all
	#@erl -pa deps/*/ebin -pa ebin -s lager -s ucp_simulator start
	@erl -pa ebin -s ucp_gateway start

