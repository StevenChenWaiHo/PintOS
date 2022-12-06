#!/bin/bash
make
rm -f build/swap.dsk
pintos-mkdisk build/swap.dsk --swap-size=128
pintos-mkdisk build/filesys.dsk --filesys-size=2

cd build/
pintos -f -q
A=${1#*\/}
exc=${A##*\/}
echo "aliasing executable ${exc}....."
pintos -p ${A} -a ${exc} -- -q
cd ../
    
cp build/filesys.dsk filesys.dsk