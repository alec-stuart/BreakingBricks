#!/bin/bash
FILENAME=$1
ORIG_STRING=".original"
cp $FILENAME $FILENAME$ORIG_STRING
GZIP_OFFSET=`binwalk -y='gzip' $FILENAME | grep rootfs| awk '{print $1;}'`
GZIP_END=`binwalk --raw="\x0B\x01\x64\x00\x00" $FILENAME | grep Raw| tail -1|awk '{print $1;}'`
ORIG_GZ_FILESIZE=`expr $GZIP_END - $GZIP_OFFSET`
echo "Original size of rootfs.img = $ORIG_GZ_FILESIZE bytes."
dd if=$FILENAME of=rootfs.img.gz skip=$GZIP_OFFSET count=$ORIG_GZ_FILESIZE bs=1
gzip -f -d rootfs.img.gz
mv rootfs.img M4R10-chroot/
chroot M4R10-chroot find  /root -type f | chroot M4R10-chroot cpio --format='newc' -o --append -F /rootfs.img
chroot M4R10-chroot find /usr/lib/libelf.so.0 -type f| chroot M4R10-chroot cpio --format='newc' -o --append -F /rootfs.img
chroot M4R10-chroot find /etc/init.d/S66asa -type f| chroot M4R10-chroot cpio --format='newc' -o --append -F /rootfs.img
mv M4R10-chroot/rootfs.img .
gzip -f -9 rootfs.img
mv rootfs.img.gz rootfs.img
NEW_FILESIZE=$(stat -c%s "rootfs.img")
echo "New size of rootfs.img = $NEW_FILESIZE bytes."
SIZE_DIFF=`expr $ORIG_GZ_FILESIZE - $NEW_FILESIZE`
ZERO=0
if test $SIZE_DIFF -lt $ZERO
then
echo "New rootfs.img is too large for existing image.."
else
# append NULLS to the size difference..
dd if=/dev/zero bs=1 count=$SIZE_DIFF  conv=notrunc,noerror status=noxfer >> "rootfs.img"
NEW_FILESIZE=$(stat -c%s "rootfs.img")
dd if=rootfs.img of=$FILENAME seek=$GZIP_OFFSET count=$NEW_FILESIZE bs=1 conv=notrunc,noerror
echo "Done!"
fi

