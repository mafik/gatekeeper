all : gatekeeper

gatekeeper : src/*.cc src/*.hh generated/embedded.hh generated/embedded.cc Makefile
	clang++-17 -std=c++2b -static -g -gdwarf-4 -O0 -ffunction-sections -fdata-sections -flto -Wl,--gc-sections src/*.cc generated/*.cc -l systemd -L. -o $@

gatekeeper-debug : src/*.cc src/*.hh generated/embedded.hh generated/embedded.cc Makefile
	clang++-17 -std=c++2b -g -gdwarf-4 -O0 -ffunction-sections -fdata-sections -flto -Wl,--gc-sections src/*.cc generated/*.cc -l systemd -L. -o $@

# Note: command for crushing png files
# pngcrush -ow -rem alla -brute -reduce static/*
generated/embedded.hh generated/embedded.cc : gatekeeper.service static/* generate_embedded.py
	./generate_embedded.py

clean :
	rm -f gatekeeper

gatekeeper.tar.gz : gatekeeper gatekeeper.service
	tar -czf $@ $^

test : gatekeeper test_e2e.sh
	sudo ./test_e2e.sh

# Rules used by maf for development

maf-run : gatekeeper
	sudo PORTABLE=1 LAN=enxe8802ee74415 ./gatekeeper

maf-debug : gatekeeper
	sudo PORTABLE=1 LAN=enxe8802ee74415 gdb ./gatekeeper -q -ex run

maf-valgrind : gatekeeper-debug
	sudo PORTABLE=1 LAN=enxe8802ee74415 valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./gatekeeper-debug

maf-massif : gatekeeper-debug
	sudo PORTABLE=1 LAN=enxe8802ee74415 valgrind --tool=massif --stacks=yes --massif-out-file=massif-out.txt ./gatekeeper-debug

maf-deploy : gatekeeper.tar.gz
	scp gatekeeper.tar.gz root@protectli:~/
	# extract into /opt/gatekeeper
	ssh root@protectli 'cd /opt/gatekeeper && tar -xzf ~/gatekeeper.tar.gz && rm ~/gatekeeper.tar.gz'

maf-reset:
	sudo nft delete table gatekeeper
	sudo ip addr flush dev enxe8802ee74415
