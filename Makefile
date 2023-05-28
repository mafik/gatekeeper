all : gatekeeper

gatekeeper : *.cc *.hh
	clang++-17 -std=c++2b -g -O0 *.cc -lcrypto -o $@

debug : gatekeeper
	sudo gdb ./gatekeeper -q -ex run

run : gatekeeper
	sudo ./gatekeeper

clean :
	rm -f gatekeeper
