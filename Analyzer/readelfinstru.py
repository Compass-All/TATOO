from itertools import count
import idc
from idaapi import *
from idautils import *
import json

res = []
flag = 0
countjcj=0



JMPS = (
    RISCV_jal,
    RISCV_jalr
)

# Conditional jump instructions
CJMPS = (
    RISCV_beq,
    RISCV_bne,
    RISCV_blt,
    RISCV_bge,
    RISCV_bltu,
    RISCV_bgeu,
    RISCV_beqz,
    RISCV_bnez,
    RISCV_blez,
    RISCV_bgez,
    RISCV_bltz,
    RISCV_bgtz
)

# Return instructions
RETS = (
    idaapi.NN_retn,   # Return Near from Procedure
    idaapi.NN_retf,   # Return Far from Procedure
    idaapi.NN_retnw,
    idaapi.NN_retnd,
    idaapi.NN_retnq,
    idaapi.NN_retfw,
    idaapi.NN_retfd,
    idaapi.NN_retfq
)

# Call Instructions
CALLS = (
    idaapi.NN_call,    # Call Procedure
    idaapi.NN_callfi,  # Indirect Call Far Procedure
    idaapi.NN_callni   # Indirect Call Near Procedure
)
instcount=0


#sub_* is the ida pro extract function, may affect the number of function need to instrumentation. hope that there not similar function name. 
for seg in Segments():
    if 'text' in idc.get_segm_name(seg):
        for func in Functions(idc.get_segm_start(seg),idc.get_segm_end(seg)):

            matchObj = re.match( r'sub_(.*)',idc.get_func_name(func), re.M|re.I)
            if(matchObj):
                print("nop")
            else:
                res.append(idc.get_func_name(func))
            


thisdict = dict.fromkeys(res)

# count the instrution number of each function
for seg in Segments():
    if 'text' in idc.get_segm_name(seg):
        for func in Functions(idc.get_segm_start(seg),idc.get_segm_end(seg)):

            dism_addr = list(FuncItems(func))
            for line in dism_addr:
                instcount = instcount + 1
                ins = ida_ua.insn_t()
                idaapi.decode_insn(ins, line)
            funcname=idc.get_func_name(func)
            matchObj1 = re.match( r'sub_(.*)',idc.get_func_name(func), re.M|re.I)
            if(matchObj1):
                print("nop")
            else:
                thisdict[funcname] = instcount    
            instcount = 0
    

print(thisdict)

with open('instru.json','w') as fp:
    json.dump(thisdict,fp)



