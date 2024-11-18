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

```
@inproceedings{wu2024tatoo,
  title={Tatoo: A Flexible Hardware Platform for Binary-Only Fuzzing},
  author={Wu, Jinting and Zheng, Haodong and Wang, Yu and Yue, Tai and Zhang, Fengwei},
  booktitle={Proceedings of the 61st ACM/IEEE Design Automation Conference},
  pages={1--6},
  year={2024}
}
```



## Reference

[1] PHMon: A Programmable Hardware Monitor and Its Security Use Cases.

https://github.com/bu-icsg/PHMon 

[2] Lowrisc 

https://github.com/lowRISC/lowrisc-chip/tree/debug-v0.3

https://github.com/lowRISC/lowrisc-chip/tree/minion-v0.4
