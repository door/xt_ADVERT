
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR  := ${MODULES_DIR}/build

obj-m += xt_ADVERT.o

ccflags-y := -Wall -g -O -std=gnu99 -Wno-declaration-after-statement


all: libxt_ADVERT.so
	make -C ${KERNEL_DIR} M=$$PWD;

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;

clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -f *.o *.so

install: modules_install
	install libxt_ADVERT.so /lib/xtables/


LIBXT_DEPFLAGS = -Wp,-MMD,$(@D)/.$(@F).d,-MT,$@

LIBXT_CFLAGS = -std=gnu99 -O2 -Wall -Wno-unused-function

lib%.so: lib%.o
	$(CC) -shared -fPIC -o $@ $^

lib%.o: lib%.c
	$(CC) ${LIBXT_DEPFLAGS} ${LIBXT_CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<
