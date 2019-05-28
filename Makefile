obj-m :=hello4.o
KERNELDIR :=/lib/modules/`uname -r`/build
PWD :=$(shell pwd)
default:
	 make -C ${KERNELDIR} M=${PWD} modules
clean:
	rm -f *.o *.ko *.mod.c *.mod.o modules.*  Module.*

