# source .env
# make -C ../buildroot menuconfig
# CONFIG=br_qemu_x86_64_defconfig
CONFIG=qemu_x86_64_latest_defconfig

mkdir -p output
# cp local.mk.tmp output/local.mk
if [ ! -f output/.config ];then
    echo "no previuse config found, configuring with ${CONFIG}"
    make BR2_EXTERNAL=$PWD O=$PWD/output -C ../buildroot $CONFIG
else
    echo "previuse config found, leaving"
    export "BR2_EXTERNAL=$PWD"
fi
