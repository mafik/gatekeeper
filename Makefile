all : gatekeeper

gatekeeper : *.cc *.hh Makefile
	clang++-17 -std=c++2b -static -g -gdwarf-4 -O0 -ffunction-sections -fdata-sections -flto -Wl,--gc-sections *.cc -l systemd -L. -o $@

gatekeeper-debug : *.cc *.hh Makefile
	clang++-17 -std=c++2b -g -gdwarf-4 -O0 -ffunction-sections -fdata-sections -flto -Wl,--gc-sections *.cc -l systemd -L. -o $@

clean :
	rm -f gatekeeper

gatekeeper.tar.gz : gatekeeper gatekeeper.gif favicon.ico style.css gatekeeper.service htmx-1.9.2.min.js
	tar -czf $@ $^

test : gatekeeper test_e2e.sh
	sudo ./test_e2e.sh

# Rules used by maf for development

maf-run : gatekeeper
	sudo ./gatekeeper enxe8802ee74415

maf-debug : gatekeeper
	sudo gdb ./gatekeeper -q -ex "run enxe8802ee74415"

maf-valgrind : gatekeeper-debug
	sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./gatekeeper-debug enxe8802ee74415

maf-massif : gatekeeper-debug
	sudo valgrind --tool=massif --stacks=yes --massif-out-file=massif-out.txt ./gatekeeper-debug enxe8802ee74415

maf-deploy : gatekeeper.tar.gz
	scp gatekeeper.tar.gz root@protectli:~/
	# extract into /opt/gatekeeper
	ssh root@protectli 'cd /opt/gatekeeper && tar -xzf ~/gatekeeper.tar.gz && rm ~/gatekeeper.tar.gz'
