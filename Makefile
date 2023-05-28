all : gatekeeper

gatekeeper : *.cc *.hh Makefile
	clang++-17 -std=c++2b -static -g -O0 *.cc -lcrypto -o $@

debug : gatekeeper
	sudo gdb ./gatekeeper -q -ex run

run : gatekeeper
	sudo ./gatekeeper enxe8802ee74415

clean :
	rm -f gatekeeper

gatekeeper.tar.gz : gatekeeper knight.gif favicon.ico style.css gatekeeper.service
	tar -czf $@ $^

deploy : gatekeeper.tar.gz
	scp gatekeeper.tar.gz root@protectli:~/
	# extract into /root/gatekeeper
	ssh root@protectli 'cd /root/gatekeeper && tar -xzf ~/gatekeeper.tar.gz && rm ~/gatekeeper.tar.gz'
