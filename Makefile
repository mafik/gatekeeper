all : gatekeeper

gatekeeper : *.cc *.hh Makefile
	clang++-17 -std=c++2b -static -g -O0 *.cc -lcrypto -o $@

debug : gatekeeper
	sudo gdb ./gatekeeper -q -ex run

run : gatekeeper
	sudo ./gatekeeper enxe8802ee74415

clean :
	rm -f gatekeeper
