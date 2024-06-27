### bbl
bbl.patch 
1. modify the MHz of system clock. 
+  *(uart_base_ptr + UART_DLL) = 50*1000*1000u / (16u * 115200u) % 0x100u;
+  *(uart_base_ptr + UART_DLM) = 50*1000*1000u / (16u * 115200u) >> 8;
2. modify the mstatus register to support custom instruction. 
+  ms = INSERT_FIELD(ms, MSTATUS_XS, 3);
3. delegate the coprocessor interrupt to the S mode so that the kernel can handle it.
+  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_MCIP;
+#define LOW_IRQ_OK(n) ((n) == IRQ_S_SOFT || (n) == IRQ_S_TIMER  || (n) == IRQ_COP)


### linux
linux.patch

fs/exec.c
monitor program
> 	//fuzzing experience
> 	if (!current->monitor_init & 
> 	((strcmp(current->comm, "size") == 0) || 
> 	 (strcmp(current->comm, "nm-new") == 0)  || 
> 	 (strcmp(current->comm, "objdump") == 0) ||
> 	 (strcmp(current->comm, "readelf") == 0) ||
> 	 (strcmp(current->comm, "nasm") == 0)    ||
> 	 (strcmp(current->comm, "tiff2bw") == 0) ||
> 	 (strcmp(current->comm, "tiffinfo") == 0)||
> 	 (strcmp(current->comm, "bison") == 0)))
> 	{
> 		current->monitor_init = true;
> 		current->monitor_enable = true;
> 		// printk("TATTO has enabled\n");
> 
> 	}


kernel/exit.c
disable the coprocessor and disable the monitor

> 	if (current->monitor_enable) {
> 		current->monitor_init = false;
> 		current->monitor_enable = false;
> 		komodo_disable_all();
> 
> 	}



core.c


enable/disable the coprocessor when the monitored program context switch.
> 	if (prev->monitor_enable) {
> 		komodo_disable_all();  
> 	}

....


> 	if (current->monitor_enable) {
> 	        komodo_enable_all();
> 	        asm volatile ("slli x0, x1, 0");
> 	}


drivers/tatoo.c