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


filterfuncnameplt=[]
for seg in Segments():
    if 'plt' in idc.get_segm_name(seg):
        for func in Functions(idc.get_segm_start(seg),idc.get_segm_end(seg)):
            filterfuncnameplt.append(idc.get_func_name(func))

with open('lib.json') as fp:
    #该方法传入一个文件对象
    dict_lib = json.load(fp)

filterfuncnamefromlib = list(dict_lib)
filterfuncname=filterfuncnamefromlib+filterfuncnameplt
with open('dict.json') as fp:
    #该方法传入一个文件对象
    dict = json.load(fp)

key_value = list(dict)
print(key_value)
for seg in Segments():
    if 'text' in idc.get_segm_name(seg):
        for func in Functions(idc.get_segm_start(seg),idc.get_segm_end(seg)):
            if idc.get_func_name(func) in key_value:
                #print(1)
                dism_addr = list(FuncItems(func))
                for line in dism_addr:
                    instcount = instcount + 1
                    ins = ida_ua.insn_t()
                    idaapi.decode_insn(ins, line)     
                    #res.append(str(ins.itype)+" "+idc.generate_disasm_line(line, 0))
                    if ins.itype in JMPS or ins.itype in CJMPS:
                        instcount=instcount+1
                        ##jump locate not equal to plt or libfuntion
                        if ins.itype ==  RISCV_jal:
                            if (idc.generate_disasm_line(line, 0).split("             ")[1] in filterfuncnameplt):
                                #print("ahfkd %x"  %(idc.generate_disasm_line(line, 0).split("             ")[1] in filterfuncnameplt))
                                #print("gifgh %s"  %(idc.generate_disasm_line(line, 0).split("             ")[1]))
                                continue
                        #res.append(str(hex(line))+"  "+idc.generate_disasm_line(line, 0))
                        res.append(line)
                        print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
                        countjcj=countjcj+1

print("count %d" %(countjcj))
print("intst %d" %(instcount))
print(res)
dict1={}

textstart=0
for s in Segments():
    if 'text' in idc.get_segm_name(s):
        textstart= idc.get_segm_start(s)

print(textstart)
#initialize the dict
for i in res:
    dictkey=i>>3<<3
    #print("%x  %d" %(dictkey,dict1[dictkey]))
    dict1[dictkey-textstart]=0
  
#print(dict1)
for i in res:
    dictkey=i>>3<<3
    #print(i&7)
    if i&7==4:
        dict1[dictkey-textstart]=dict1[dictkey-textstart]+4#i&7 
    else:
        dict1[dictkey-textstart]=dict1[dictkey-textstart]+1
print("after " )
#print(dict1)

with open('pc1.txt','w') as fp:
    for key in dict1:
       fp.write(str(key)+" "+str(dict1[key])+"\n")
#with open('pc1.txt','a') as fp:
#    fp.write("@")
'''
with open('dis1.txt','w') as f:
    for i in range(0,len(res)):
       f.write(res[i]+"\n")
'''


