KERNEL_DIR = /lib/modules/`uname -r`/build
MODULEDIR := $(shell pwd)

.PHONY: modules start stop
default: modules

modules:
	make -C $(KERNEL_DIR) M=$(MODULEDIR) modules

clean distclean:
	rm -f *.o *.mod.c .*.*.cmd *.ko *.ko.unsigned
	rm -rf .tmp_versions
	rm -f he *.order *.symvers .*.cmd

start:
	sudo insmod ./http_stat.ko
	sudo echo `pwd`/conf > /proc/http_stat/confdir

stop:
	sudo rmmod http_stat
