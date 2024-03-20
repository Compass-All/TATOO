CFLAGS="-O3 -ggdb" ./configure --disable-system   --enable-linux-user --disable-gtk --disable-sdl --disable-vnc   --target-list="riscv64-linux-user" --host=riscv64-unknown-linux-gnu --enable-pie
