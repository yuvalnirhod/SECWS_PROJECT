obj-m += firewall.o
firewall-objs := ./src/hw3secws.o ./src/parser.o ./src/Logs.o ./src/Hook.o ./src/connectionTable.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
