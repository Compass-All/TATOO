#! /bin/bash
mknod /dev/mmcblk0p1 b 179 1
mkdir /mnt
mount /dev/mmcblk0p1 /mnt
mknod  -m 644  /dev/urandom  c 1 9
mknod /dev/mem -m666 c 1 1
mkdir -v /dev/shm
mount -vt tmpfs none /dev/shm
dd if=/dev/zero of=/dev/shm/my_dir_shm_name bs=110000 count=1

