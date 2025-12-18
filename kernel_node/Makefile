obj-m += attest_lkm.o

attest_lkm-objs := src/attest_lkm.o src/netlink_comm.o src/measure.o src/hooks.o

KERNEL_VERSION := 6.17.6-200.fc42.x86_64
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
SIGN_FILE := $(KDIR)/scripts/sign-file

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod attest_lkm.ko

uninstall:
	sudo rmmod attest_lkm

reload: uninstall install

sign:
	@echo "Signing module..."
	@if [ ! -f $(SIGN_FILE) ]; then \
		echo "ERROR: sign-file script not found at $(SIGN_FILE)"; \
		echo "Install with: sudo dnf install kernel-devel-$(KERNEL_VERSION)"; \
		exit 1; \
	fi
	sudo $(SIGN_FILE) sha256 keys/MOK.priv keys/MOK.der attest_lkm.ko
	@echo "Module signed successfully"
