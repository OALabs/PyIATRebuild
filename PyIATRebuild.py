#!/usr/bin/env python

############################################################################################################################################
##
##   _______  __   __  ___   _______  _______    ______    _______  _______  __   __  ___   ___      ______  
##  |       ||  | |  ||   | |   _   ||       |  |    _ |  |       ||  _    ||  | |  ||   | |   |    |      | 
##  |    _  ||  |_|  ||   | |  |_|  ||_     _|  |   | ||  |    ___|| |_|   ||  | |  ||   | |   |    |  _    |
##  |   |_| ||       ||   | |       |  |   |    |   |_||_ |   |___ |       ||  |_|  ||   | |   |    | | |   |
##  |    ___||_     _||   | |       |  |   |    |    __  ||    ___||  _   | |       ||   | |   |___ | |_|   |
##  |   |      |   |  |   | |   _   |  |   |    |   |  | ||   |___ | |_|   ||       ||   | |       ||       |
##  |___|      |___|  |___| |__| |__|  |___|    |___|  |_||_______||_______||_______||___| |_______||______| 
## 
##
##  ========================== Brute forcing absolute memory addresses since 2017! ==========================
##
##
##  Use this library to rebuild the import address table for a PE dumped from memory. 
##
##  WARNING! I only wrote this because I couldn't find an existing tool with python bindings. 
##  This is not a replacement for ImpREC. ImpREC will always be a better choice because it's awesome 
##  and eats malware for breakfast while shooting lasers out of it's eyes!! 
##  Only use this inferior tool if you need to do some automated reconstruction via python.
##  
##  This library must be run _on_the_host_ where the PE is being dumped and the process that the PE 
##  was dumped from must still be active. **The setup is the same as the famous ImpREC tool.
##  
##  For this library to work you will need to have a valid PE file (as a binary string). 
##  "Valid" means that the PE file must already be in its unmapped format with a valid base address. 
##  You will also need the process that the PE was dumped from to still be active.
##
##  WARNING Part 2! Currently pyIAT_Rebuild does not handle relocation : (
##
#############################################################################################################################################

import sys
import struct
import argparse
import os

# This is not cross platform! 
# How can you attach to PE process on anything but windows :)
# If you try to force this you will find some nice evil errors with winappdbg at execution time...
assert sys.platform == "win32", "This library can only be run on Windows!"

from winappdbg import System, Process

from elfesteem import pe_init

try:
    import distorm3
except ImportError as e:
    raise ImportError('''Cannot import module distorm3. 
        Pro-tip: on Windows instead of attempting to install via pip download and execute the installer from: 
            https://pypi.python.org/pypi/distorm3''')


__AUTHOR__ = '@herrcore'
__VERSION__ = 0.1



#############################################################################################################################################
#
# Functions _call_or_unc_jmp and call_scan are heavily influnced and partially copied from the volitility plugin "impscan.py"
#
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2010 - 2012 Michael Ligh <michael.ligh@mnin.org>
#
# https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/malware/impscan.py
#
#############################################################################################################################################
def _call_or_unc_jmp(op):
    """Determine if an instruction is a call or an
    unconditional jump
    @param op: a distorm3 Op object
    """
    return ((op.flowControl == 'FC_CALL' and op.mnemonic == "CALL") or  (op.flowControl == 'FC_UNC_BRANCH' and  op.mnemonic == "JMP"))


def call_scan(data_vr_address, data):
    """Disassemble a block of data and yield possible 
    calls to imported functions. We're looking for 
    instructions such as these:
    x86:
    CALL DWORD [0x1000400]
    JMP  DWORD [0x1000400]
    """
    iat_ptrs=[]
    end_address = data_vr_address + len(data)
    mode = distorm3.Decode32Bits
    for op in distorm3.DecomposeGenerator(data_vr_address, data, mode):
        if not op.valid:
            continue
        iat_loc = None
        if (_call_or_unc_jmp(op) and op.operands[0].type == 'AbsoluteMemoryAddress'):
            iat_loc = (op.operands[0].disp) & 0xffffffff
        if (not iat_loc or (iat_loc < data_vr_address) or (iat_loc > end_address)):
            continue
        # resolve iat_loc to API
        #print iat_loc
        if iat_loc not in iat_ptrs:
            iat_ptrs.append(iat_loc)
    return iat_ptrs


def _iat_candidate(op):
    """Determine if an instruction is able to reference an IAT pointer
    @param op: a distorm3 Op object
    """
    return (op.mnemonic == "CALL") or  (op.mnemonic == "JMP") or  (op.mnemonic == "MOV") or  (op.mnemonic == "PUSH") or  (op.mnemonic == "LEA")

def reslove_iat_pointers(pid, iat_ptrs):
    """Use winappdbg to resolve IAT pointers to their respective module and function names
    @param pid: process ID to connect to
    @param iat_ptrs: list of pointer addresses to be resolved
    """
    ######################################################################
    #
    # Attach to process and start using winappdbg
    #
    ######################################################################
    # Request debug privileges.
    System.request_debug_privileges()

    # Attach to process
    process = Process(pid)
    # Lookup the process modules.
    process.scan_modules()

    # imp_table[ <funct_pointer> ] = [ <module_name>, <function_name> ] 
    imp_table = {}
    for iat_ptr in iat_ptrs:
        # For each iat pointer get the function name as a label populated by winappdbg
        label = process.get_label_at_address(process.peek_dword(iat_ptr))
        module,function,offset = Process.split_label_strict(label)
        # Only add functions that have valid labels
        if function != None:
            imp_table[iat_ptr] = [module, function]

    
    ######################################################################
    #
    # Because we may have missed some IAT pointers with our scanner we 
    # are going to attempt to locate the full mapped IAT directory in the 
    # section then enumerate ever pointer in the directory. And use that 
    # list instead. 
    #
    ######################################################################
    imp_table_new={}
    for iat_ptr in range(min(imp_table.keys()), max(imp_table.keys())+4, 4):
        # Resolve the requested label address.
        label = process.get_label_at_address(process.peek_dword(iat_ptr))
        module,function,offset = Process.split_label_strict(label)
        if function != None:
            imp_table_new[iat_ptr] = [module, function]
    return imp_table_new


def rebuild_iat(pid, pe_data, base_address, oep):
    """
    @param pid: process ID for winappdbg to attach to and dump IAT offsets
    @param pe_data: full PE file read in as a binary string
    @param base_address: base address of PE (this override the base addres set in the pe_data)
    @param oep: original entry point of the PE (this override the base addres set in the pe_data)
    """

    # TODO: this load wants the PE in mapped format, we need to update instructions or update the loadfrommem param
    pf = pe_init.PE(loadfrommem=True, pestr=pe_data)

    pf.NThdr.ImageBase = base_address

    # get offset to oep
    rva_oep = oep - base_address

    pf.Opthdr.AddressOfEntryPoint = rva_oep

    # clear the existing import table
    # there are two different versions of elfesteem one that uses an extra .l[] object
    # and one that does not. If we get the wrong one, just catch the error and continue.
    try:
        pf.DirImport.impdesc.l=[]
    except:
        pf.DirImport.impdesc =[]
    ######################################################################


    pdata = None 
    data_vr_addr = None
    data_rva = None
    # locate section that contains OEP 
    for tmp_sec in pf.SHList:
        tmp_start = tmp_sec.addr
        tmp_end = tmp_start + tmp_sec.size
        if (rva_oep >= tmp_start) and (rva_oep <= tmp_end):
            try:
                pdata = pf._rva.get(tmp_start,tmp_sec.size)
            except AttributeError as e:
                raise AttributeError("You are using the wrong version of elfesteem, don't use pip instead install from https://github.com/serpilliere/elfesteem")
            data_vr_addr = base_address + tmp_start
            data_rva = tmp_start
            break

    # make sure we have found the correct section
    # WARNING! if the pdata section is not the same as the one loaded in memory the IAT extraction will
    #          fail because the addresses and offsets will be wrong.
    assert pdata != None, "Unable to locate rva_oep: 0x%x in sections: %s" % (rva_oep, pf.SHList)

    # find all call/jmp to possible IAT function pointers
    # iat_ptrs is a list of all the addresses that are potential IAT pointers
    iat_ptrs = call_scan(data_vr_addr, pdata)

    imp_table = reslove_iat_pointers(pid, iat_ptrs)

    

    # Create a table with module names as the keys and all the functions assigned accordingly
    #[module]:[func1, func2, ...]
    mod_table = {}
    for iat_ptr in imp_table.keys():
        # TODO: it is possbile some module names may end with somethin other than .dll
        tmp_mod = imp_table[iat_ptr][0]+".dll"
        tmp_fn = imp_table[iat_ptr][1]
        if tmp_mod in mod_table.keys():
            f_arr = mod_table[tmp_mod]
            # Only add function name if it isn't already assigned
            if tmp_fn not in f_arr:
                f_arr.append(tmp_fn)
                mod_table[tmp_mod] = f_arr
        else:
            mod_table[tmp_mod] = [tmp_fn]

    newiat_rawsize = (( (len(imp_table.keys()) * 4 ) / 0x1000) + 1) * 0x1000
    # Create new section to hold new IAT 
    s_newiat = pf.SHList.add_section(name="newiat", rawsize=newiat_rawsize)

    ######################################################################
    #
    # elfesteem.PE has a special format for describing the IAT directory
    # We are converting the mod_table into that format...
    #
    ######################################################################
    new_dll=[({"name": mod_table.keys()[0],"firstthunk": s_newiat.addr}, mod_table[mod_table.keys()[0]])]
    for mod in mod_table.keys()[1:]:
        tmp_entry = ({"name": mod,"firstthunk": None}, mod_table[mod])
        new_dll.append(tmp_entry)

    ######################################################################
    #
    # Add the new imports table directory to PE file
    #
    ######################################################################
    pf.DirImport.add_dlldesc(new_dll)
    newimpdir_rawsize = ((len(pf.DirImport) / 0x1000) + 1) * 0x1000
    s_newimpdir = pf.SHList.add_section(name="newimpdir", rawsize=newimpdir_rawsize)
    pf.SHList.align_sections(0x1000, 0x1000)
    pf.DirImport.set_rva(s_newimpdir.addr)
    

    ######################################################################
    #
    # Create a mapping from the old IAT pointers to the new ones
    # iat_map[ <old_pointer> ] = <new_pointer>
    #
    ######################################################################
    iat_map ={}
    for iat_ptr in imp_table.keys():
        if imp_table[iat_ptr][1] == None:
            continue
        tmp_mod = imp_table[iat_ptr][0]+".dll"
        tmp_fn = imp_table[iat_ptr][1]
        try:
            iat_map[iat_ptr] = pf.DirImport.get_funcvirt(tmp_mod, tmp_fn)
        except:
            continue

    # If there is some error building the module map stop!
    assert iat_map != {}, "The iat_map is empty, we are unable to find the new IAT pointers for the old pointers in imp_table."


    ######################################################################
    #
    # Patch the code section in the PE and replace all references to the 
    # old IAT pointers with references to the new pointers.
    #
    ######################################################################
    # Make a copy of the code data to work on
    odata = pdata

    mode = distorm3.Decode32Bits
    for op in distorm3.DecomposeGenerator(data_vr_addr, pdata, mode):
        if not op.valid:
            continue
        iat_loc = None
        if _iat_candidate(op):
            for operand in op.operands:
                test_operand = operand.disp & 0xffffffff
                if test_operand in iat_map.keys():
                    #print "Fixing IAT pointer for: %s" % op
                    #op_ptr = op.address - base_address
                    #TODO: is this right??
                    op_ptr = op.address - data_vr_addr
                    op_size = op.size
                    orig_op = odata[op_ptr:op_ptr+op_size]
                    orig_operand = struct.pack('<I',test_operand)
                    new_operand = struct.pack('<I',iat_map[test_operand])
                    new_op = orig_op.replace(orig_operand, new_operand)
                    odata = odata[:op_ptr] + new_op + odata[op_ptr+op_size:]
                    #stop testing operands
                    break

    # Copy the patched section back to the PE
    pf._rva.set(data_rva,odata)

    # Disable rebase, since addresses are absolute any rebase will make this explode
    pf.NThdr.dllcharacteristics = 0x0
    return str(pf)





def main():
    parser = argparse.ArgumentParser(description="Simple example of PyIATRebuild library in use!")
    parser.add_argument("infile", help="The file to fix IAT.")
    parser.add_argument("outfile", help="The file to write results.")
    parser.add_argument('--pid',dest="in_pid",type=int,default=None,required=True,help="Specify process ID to export IAT from.")
    parser.add_argument('--base_address',dest="in_base_address",type=int,default=None,required=True,help="Specify base address the process is loaded at (will overwrite PE).")
    parser.add_argument('--oep',dest="in_oep",type=int,default=None,required=True,help="Specify original entry point for process, virtual address not RVA (will overwrite PE).")
    args = parser.parse_args()

    with open(args.infile,"rb") as fp:
        pe_data= fp.read()

    new_pe_data = rebuild_iat(args.in_pid, pe_data, args.in_base_address, args.in_oep)

    open(args.outfile, 'wb').write(new_pe_data)

if __name__ == '__main__':
    main()

















