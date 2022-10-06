#!/bin/bash
FACTORY_IMAGE="oriole-sd1a.210817.015.a4-factory-074b7f51.zip"
if [ ! -f $FACTORY_IMAGE ]; then
    echo "Retrieving factory image"
    wget "https://dl.google.com/dl/android/aosp/oriole-sd1a.210817.015.a4-factory-074b7f51.zip"
fi

if [ ! -f imjtool.ELF64 ]; then
    wget "http://newandroidbook.com/tools/imjtool.tgz"
    tar xzf imjtool.tgz imjtool.ELF64
fi

IMJTOOL=$(pwd)/imjtool.ELF64

TMPDIR=$(pwd)/tmp
VERSION=$(echo $FACTORY_IMAGE | cut -d '.' -f 2)
unzip $FACTORY_IMAGE 'oriole*/bootloader*' -d $TMPDIR
cd $TMPDIR
$IMJTOOL oriole*/bootloader-oriole*.img extract
mv extracted/abl ../abl_$VERSION
cd -

rm -fr imjtool.tgz $TMPDIR
RES=$(md5sum abl_210817)
if [ "$RES" == "0f67aea80ead54b12899efd8647cfec4  abl_210817" ]; then
    echo "Integrity OK"
else
    echo "Wrong hash 0f67aea80ead54b12899efd8647cfec4 was expected"
fi
