
KBUILD:=/lib/modules/$(shell uname -r)/build/

CFLAGS_xnic.o += -Wfatal-errors
CFLAGS_xnic.o += -Werror
CFLAGS_xnic.o += -Wall
CFLAGS_xnic.o += -Wextra
CFLAGS_xnic.o += -Wno-declaration-after-statement
CFLAGS_xnic.o += -Wno-error=unused-parameter
CFLAGS_xnic.o += -Wno-error=unused-function
CFLAGS_xnic.o += -Wno-error=unused-label
CFLAGS_xnic.o += -Wno-type-limits
CFLAGS_xnic.o += -Wno-unused-parameter
CFLAGS_xnic.o += -Wno-sign-compare
CFLAGS_xnic.o += -mpopcnt

obj-m += xnic.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
