# Build
make clean && make

# Sign
make sign

# Load
sudo insmod attest_lkm.ko

# Verify
lsmod | grep attest
dmesg | tail -20
