
KBUILD := /lib/modules/$(shell uname -r)/build/

CONFIG_XLAN := m

CFLAGS_xlan.o += -Wfatal-errors
CFLAGS_xlan.o += -Werror
CFLAGS_xlan.o += -Wall
CFLAGS_xlan.o += -Wextra
CFLAGS_xlan.o += -Wno-declaration-after-statement
CFLAGS_xlan.o += -Wno-error=unused-parameter
CFLAGS_xlan.o += -Wno-error=unused-function
CFLAGS_xlan.o += -Wno-error=unused-label
CFLAGS_xlan.o += -Wno-type-limits
CFLAGS_xlan.o += -Wno-unused-parameter
CFLAGS_xlan.o += -Wno-sign-compare
CFLAGS_xlan.o += -Wno-implicit-fallthrough
CFLAGS_xlan.o += -mpopcnt

obj-$(CONFIG_XLAN) += xlan.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
