all : gatekeeper

gatekeeper : *.cc *.hh Makefile
	clang++-17 -std=c++2b -static -g -O0 *.cc -o $@

debug : gatekeeper
	sudo gdb ./gatekeeper -q -ex run

clean :
	rm -f gatekeeper

gatekeeper.tar.gz : gatekeeper gatekeeper.gif favicon.ico style.css gatekeeper.service
	tar -czf $@ $^

# Rules used by maf for development

maf-run : gatekeeper
	sudo ./gatekeeper enxe8802ee74415

maf-deploy : gatekeeper.tar.gz
	scp gatekeeper.tar.gz root@protectli:~/
	# extract into /opt/gatekeeper
	ssh root@protectli 'cd /opt/gatekeeper && tar -xzf ~/gatekeeper.tar.gz && rm ~/gatekeeper.tar.gz'
