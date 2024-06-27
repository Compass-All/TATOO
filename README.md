# TATOO-prototype
### Overview:

Our prototype is built from Programmable Hardware Monitor (PHMon) and Lowrisc. We run our experiments on the Xilinx Kintex-7 FPGA KC705 evaluation board. Considering code size, we only show the necessary modifications in this repository.

Although we have extensively tested the code, Tatoo is a research prototype and is likely to contain bugs. Moreover, due to the significant challenges associated with testing modifications to hardware code, there may be some instability in fuzz testing. If you encounter any issues, please do not hesitate to contact us. We are in the process of submitting the code and will make every effort to complete the submission by the end of June.

## Contents

- `Lowrisc-chip`: patches for Lowrisc.
- `kernel.patch`: patches for Linux Kernel.
- `bootloader.patch`: patches for RISC-V Open Source Supervisor Binary Interface.
- `Bitstreams`: generated bitstreams.
- `Configrer`: the cofiguration file to config the coprocessor.
- `AFL-modification`: necessary modification on AFL.
- `Analyzer`: the idapython script to analyze the branch instruction and jump instruction.
- `Tagger`: the script that write the tag into memory. 
- `Evaluation`: some script about running experiment; some modification about AFL_QEMU to run the experiement.

## Preparation

1. install vivado
download vivado and install vivado_ubuntu_JTAG/UART driver
Uart: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
Jtag: http://training.eeworld.com.cn/video/15232
2. download lowrisc-chip
3. download riscv-gnu-toolchain
4. download busybox
5. download linux 4.6
6. download AFL
7. download QEMU 4.1.1 to run AFL-QEMU in FPGA
## Others
- https://github.com/eugene-tarassov/vivado-risc-v: commit 1e99e190f6ef36e0142670a6446f978ffd992663
- https://github.com/llvm/llvm-project: commit fed41342a82f5a3a9201819a82bf7a48313e296b
- https://github.com/ucb-bar/rocket-chip.git: commit 1bd43fe1f154c0d180e1dd8be4b62602ce160045
- https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git: commit 07e0b709cab7dc987b5071443789865e20481119
- https://github.com/lowRISC/riscv-gnu-toolchain.git: commit ff21e26eb8c4d55dad7ad0b57e7bd8f7784a60e9
- https://github.com/lowRISC/lowrisc-chip/tree/kc705_update
- https://github.com/lowRISC/lowrisc-chip: commit b4d89f25f431a3f29ce72f1ce6dece1c439d788f
- https://github.com/jim-wilson/riscv-linux-native-gdb.git: commit 82e1308f1b595049b0a1deedd6b391bdd27855fa
- https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.6.2.tar.xz : curl https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.6.2.tar.xz | tar -xJ

## Usage

Make sure to install riscv-gnu-toolchain[lowrisc toolchain] and linux-4.6 and set RISCV variable in advance. A Xilinx Kintex-7 FPGA KC705 evaluation board, an SD card, and a Vivado installation are required. We provide the generated bitstream, linux kernel, and bootloader in the repository. 

source /opt/Xilinx/Vivado/2015.4/settings64.sh

### patch the gnu

gnu is modified to provide the 'tagr' and 'tagw' instructions.
    git apply gnu.patch

### patch the linux kernel
    patch -p1 < kernel.patch

### patch the AFL
    patch -p1 < AFL.patch

### Compile tagger    
    $ cd tagging
    $ make
    
### Compile configurer
    $ cd config/{the configurer}
    $ make
    

### Analyze the binary file
Since angr didn't support riscv64 when we do the experiment, we used idapro to analyze it.

    open file afl1. run readelfinstru.py in ida 
    open file bare2. run readelfnoinstru.py  in ida
    run fenxi.py
    run collect.py


### config the coprocessor

### enable the kernel driver
    
    mknod /dev/cmap c 254 0
    

### Tagging the program

    
    ./tagger input_file output_file tag_file
    
e,g. /mnt/tatto/copyfiles nasm.bare nasm pc1.txt

### running script
    
    mknod /dev/cmap c 254 0
    /mnt/tatto/copyfiles nasm.bare nasm pc1.txt
    /mnt/tatto/shujuliu/tattoconfig
    /mnt/tatto/shujuliu/afl_greyone -m 1024 -i /mnt/elf -o out /mnt/tatto/nasm_phmon_tatto/nasm -f elf -o sample @@
    





### Program the FPGA

Drag compiled programs and debian-riscv64-boot/ into the SD card.
Connect your KC705 with a USB cable and power it on.
Open Hardware Manager in Vivado and program FPGA with the bitstream.

### Boot linux


You can login over UART console:
    
    $ mknod /dev/cmap c 254 0
    $ sudo microcom −p /dev/ttyUSB0 −s 115200
    
after Linux boot, you can run the protected program.

## Additional Information

### Citation
If you use this repository for research, please cite our paper:


### Publication


### Paper




## Reference

[1] PHMon: A Programmable Hardware Monitor and Its Security Use Cases.

https://github.com/bu-icsg/PHMon 

[2] Lowrisc 

https://github.com/lowRISC/lowrisc-chip/tree/debug-v0.3

https://github.com/lowRISC/lowrisc-chip/tree/minion-v0.4



## Problems that may arise

1.fail to boot.
wjt debug iself64 0 e_ident[4] 0  e_ident[0] 0 e_ident[1] 0 e_ident[2]0 e_ident[3]0

it must make sure that ddr test pass
or you should change the kc705 board size to 64

fpga/board/kc705/script/make_project.tcl
lowrisc-kc705/script/make_project.tclThe set mem_data_width {128} in this project is 128, but it won't run. Change to 64.

make_project.tcl
set mem_data_width {64}

mig_config.prj <C0_S_AXI_DATA_WIDTH>64</C0_S_AXI_DATA_WIDTH>

## glibc-2.25
kernel too old

## problems we solved
### 为什么linux上的时间不准?

sleep（1）发现在板子上是20s

1.  转换误差2. 时钟不稳定3. 时钟频率不对
 2.时钟频率不对

前面的计算都是按照CCB Clock 8分频50M来计算，但是这个50M是否准确？

那就看看这个50M到底从哪来的

time_init (/arch/powerpc/kernel/time.c)

-->ppc_md.calibrate_decr(); == generic_calibrate_decr(void)

-->get_freq("timebase-frequency",1, &ppc_tb_freq)

此处获取到的ppc_tb_freq = 50M

get_freq是从设备树中读取的，但实际的设备树中并没有timebase-frequency这个选项

最终找到uboot中 fdt.c (arch/powerpc/cpu/mpc85xx)


https://zhuanlan.zhihu.com/p/61092537?ivk_sa=1024320u


## elf2hex  16 4096 $< > $@ 1073741824


fpga/bare_metal/examples


lowrisc-fpga/bare_metal/examples/Makefile
elf2hex  16 4096 $< > $@ 1073741824

https://github.com/lowRISC/lowrisc-fpga/blob/2691865d1a6692f731bb9969dc1d146385d32964/bare_metal/examples/Makefile#L70

export RISCV=/home/gjr/Desktop/gnu2018/gnu
export PATH=$PATH:$RISCV/bin


Desktop/gnu2018/riscv64-gnu-toolchain/riscv-binutils-gdb
Desktop/evaluation/config
Desktop/evaluation/tagging
/home/gjr/Documents/riscv-linux-native-gdb
/Documents/AFLX86/AFL/qemu_mode/qemu-4.1.1








If the Vivado Synthesis tool runs out of memory when running, it will often crash with a message similar to "Segmentation fault "$RDI_PROG".

Solution
The best solution is to determine what is causing the large memory usage. Often this could be a large loop in your RTL, or a timing constraint with a wildcard. 

However determining the cause is not always easy. One other possible work-around is to call up Vivado with a larger stack size. This might allow the tool to finish what it was doing.

vivado -stack 2000
https://www.xilinx.com/support/answers/64434.html


# 
