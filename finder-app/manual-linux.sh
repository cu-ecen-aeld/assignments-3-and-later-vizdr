#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u
#1
OUTDIR=${1:-/tmp/aeld} 
# Hint: set -e (exit on any error) will exit if mkdir fails
if [ ! -d "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
fi

KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

# Locate the readelf binary
READELF_PATH=$(command -v aarch64-none-linux-gnu-readelf)
if [ -z "$READELF_PATH" ]; then
    echo "aarch64-none-linux-gnu-readelf not found" >&2
    exit 1
fi

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi

if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
    echo "1st Step: Deep clean for kernel build tree"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper

    echo "2nd Step: KConfig for QEMU  - simulation"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig

    echo "3rd Step: Build a kernel image w/o bootloader, with QEMU"
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

    echo "4th Step: Build modules"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules

    echo "5th Step: Build devicetree"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs
fi

echo "6th Step: Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"

cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
echo "We create the necessary user-space directories"
mkdir -p "${OUTDIR}/rootfs"
cd "${OUTDIR}/rootfs"
mkdir -p "bin" "dev" "etc" "proc" "sbin" "sys" "tmp"
mkdir -p "lib" "lib64" "lib/modules" "lib/modules/${KERNEL_VERSION}"
mkdir -p "usr" "usr/bin" "usr/lib" "usr/sbin"
mkdir -p "var" "var/log"
mkdir -p "home" "home/conf"

echo "We configure and apply BusyBox to fill the necessary user-space directories"
cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git

    cd busybox
    git checkout ${BUSYBOX_VERSION}
    
    # TODO:  Configure busybox
    echo "We configure BusyBox"    
    make distclean
    make defconfig

else
    cd busybox
fi

# TODO: Make and install busybox
echo "We make BusyBox"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
echo "We fill rootfs with BusyBox"
make CONFIG_PREFIX="${OUTDIR}/rootfs" ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a /usr/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a /usr/bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
echo "We readout dependencies of BusyBox and copy to rootfs"
CROSS_COMPILE_FULLPATH=$(dirname $(which ${CROSS_COMPILE}readelf))
cp $CROSS_COMPILE_FULLPATH/../aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 ${OUTDIR}/rootfs/lib/ld-linux-aarch64.so.1
cp $CROSS_COMPILE_FULLPATH/../aarch64-none-linux-gnu/libc/lib64/libm.so.6 ${OUTDIR}/rootfs/lib64/libm.so.6
cp $CROSS_COMPILE_FULLPATH/../aarch64-none-linux-gnu/libc/lib64/libresolv.so.2 ${OUTDIR}/rootfs/lib64/libresolv.so.2
cp $CROSS_COMPILE_FULLPATH/../aarch64-none-linux-gnu/libc/lib64/libc.so.6 ${OUTDIR}/rootfs/lib64/libc.so.6

# TODO: Make device nodes
echo "We establish 2 device nodes"
cd "${OUTDIR}/rootfs"
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/console c 5 1

# TODO: Clean and build the writer utility
echo "We clean and build for target the writer utility"
cd $FINDER_APP_DIR
make clean
make CROSS_COMPILE=${CROSS_COMPILE}


# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
echo "We copy the finder related scripts and executables to the rootfs/home directory"
cp $FINDER_APP_DIR/finder-test.sh $FINDER_APP_DIR/finder.sh $FINDER_APP_DIR/writer.sh $FINDER_APP_DIR/writer "${OUTDIR}/rootfs/home"
cp -r $FINDER_APP_DIR/../conf "${OUTDIR}/rootfs/home"
cp $FINDER_APP_DIR/autorun-qemu.sh "${OUTDIR}/rootfs/home"
cp conf/username.txt "${OUTDIR}/rootfs/home/conf"
cp conf/assignment.txt "${OUTDIR}/rootfs/home/conf"


# TODO: Chown the root directory
echo "We provide necessary permissions for rootfs"
sudo chown root:root "${OUTDIR}/rootfs"


# TODO: Create initramfs.cpio.gz
echo "We are almost ready and pack rootfs with cpio into initramfs.cpio.gz"
cd "${OUTDIR}/rootfs"
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio

echo "!!!Completed!!!"


