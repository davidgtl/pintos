#! /bin/sh -e

if test -z "$SRCDIR" || test -z "$PINTOSDIR" || test -z "$DSTDIR"; then
    echo "usage: env SRCDIR=<srcdir> PINTOSDIR=<srcdir> DSTDIR=<dstdir> sh $0"
    echo "  where <srcdir> contains bochs-2.6.9.tar.gz"
    echo "    and <pintosdir> is the root of the pintos source tree"
    echo "    and <dstdir> is the installation prefix (e.g. /usr/local)"
    exit 1
fi

cd /tmp
mkdir $$
cd $$
BOCHS_DIR=`tar --list -f $SRCDIR/bochs-2.6.9.tar.gz | head -n 1`
tar xzf $SRCDIR/bochs-2.6.9.tar.gz
mv $BOCHS_DIR bochs-2.6.9
cd bochs-2.6.9

#CFGOPTS="--with-x --with-x11 --with-term --with-sdl --with-nogui --prefix=$DSTDIR"
#CFGOPTS="--with-x --with-x11 --with-term --with-sdl --with-nogui --enable-magic-breakpoint --prefix=$DSTDIR"

CFGOPTS="--disable-docbook --with-x --with-x11 --with-term --with-sdl --with-nogui --enable-x86-debugger --prefix=$DSTDIR"
mkdir plain &&
        cd plain &&
        ../configure $CFGOPTS --enable-gdb-stub &&
        make &&
        make install &&
        cd ..
mkdir with-dbg &&
        cd with-dbg &&
        ../configure --enable-debugger $CFGOPTS &&
        make &&
        cp bochs $DSTDIR/bin/bochs-dbg &&
        cd ..

