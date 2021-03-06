.PHONY: all clean goenv gogen vendor mocks bazel gazelle setcap

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

all: bazel

clean:
	bazel clean
	rm -f bin/*
	if [ -e go/vendor ]; then rm -r go/vendor; fi

gogen:
ifndef GOGEN_SKIP
	$(MAKE) -C go/proto
else
	@echo "gogen: skipped"
endif

goenv: vendor
	bazel fetch "kind('go_(default_library|test|binary)', //...)"

vendor:
	if [ -e go/vendor ]; then rm -r go/vendor; fi
	bzlcompat -vendorBase=go

bazel: vendor gogen
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

mocks: goenv
	./tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)
