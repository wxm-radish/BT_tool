#coding:utf-8
# import idc
import sys
import getopt
import os
from capstone import *
import time
import hashlib
import plyara

go_arch = ""
go_version = ""

def md5_encode(original_str):
    m = hashlib.md5()
    m.update(original_str.encode(encoding='UTF-8'))
    return m.hexdigest()


def print_banner():
    print(
    '''
 ____ _____              _       _     _  __   __              
| __ )_   _|            / \   __| | __| | \ \ / /_ _ _ __ __ _ 
|  _ \ | |    _____    / _ \ / _` |/ _` |  \ V / _` | '__/ _` |
| |_) || |   |_____|  / ___ \ (_| | (_| |   | | (_| | | | (_| |
|____/ |_|           /_/   \_\__,_|\__,_|   |_|\__,_|_|  \__,_|
                                                               
author:     萝卜
time:       2021.08.04  
contact:    pwntool@163.com 
''')


yara_dir = ""
current_version = ""

def fmt_name(funcname):
    funcname = funcname.replace(".","_")
    funcname = funcname.replace("/","_")
    funcname = funcname.replace("*","_")
    funcname = funcname.replace(" ","")
    funcname = funcname.replace("·","_")
    funcname = funcname.replace("[","_")
    funcname = funcname.replace("]","_")
    funcname = funcname.replace("{","_")
    funcname = funcname.replace("}","_")
    funcname = funcname.replace("-","_")
    funcname = funcname.replace(";","_")
    funcname = funcname.replace("(","_")
    funcname = funcname.replace(")","_")
    return funcname



def get_one_func_data(funcname,funcaddr):
    # funcname = "os_exec___Cmd__Output"
    # funcaddr = 0x0643180
    func_start_addr = idc.GetFunctionAttr(funcaddr, FUNCATTR_START)
    func_end_addr = idc.GetFunctionAttr(funcaddr, FUNCATTR_END)
    func_data = ""
    for x in range(func_start_addr,func_end_addr):
        tmp = ""
        tmp = "%02x" % (Byte(x))
        func_data += tmp
        # func_data += hex(Byte(x))[2:]
    func_data = func_data.decode("hex")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    func_yara = ""
    for i in md.disasm(func_data, 0):
        # print "{},0x{}:\t{}\t{}".format(i.addr_size,i.address, i.mnemonic, i.op_str)
        if i.mnemonic == "call" and i.op_str!="rax" :
            # print i.mnemonic, i.op_str
            func_yara += "E8 [4] "
        elif i.mnemonic=="lea" and i.op_str[:9]=="rax, [rip":
            # print i.mnemonic, i.op_str
            func_yara += "488D05 [4] "
        elif i.mnemonic=="lea" and i.op_str[:9]=="rcx, [rip":
            # print i.mnemonic, i.op_str
            func_yara += "488D0D [4] "
        elif i.mnemonic=="cmp" and i.op_str[:14] == "dword ptr [rip":
            # print i.mnemonic, i.op_str
            func_yara +=  func_data[i.address:i.address+2].encode("hex")+" [4] "+func_data[i.address+5].encode("hex")
            # func_yara += data[i.address:i.address+2] +  " [4] " +data[i.address+:]
        else:
            func_yara += func_data[i.address:i.address+i.size].encode("hex")
            # print data[i.address:i.address+i.size], i.mnemonic, i.op_str
    if func_yara[-5:]==" [4] ":
        func_yara = func_yara[:-5]
    # print func_yara
    yara_rule = '''rule checkfunc{
meta:
    autor = "radish"
    func_name = "%s"
    go_version = "%s"
    go_arch = "%s"
strings:
    $s1 = {%s}
condition:
    any of them
}
'''%(funcname,go_version,go_arch,func_yara)
    # print_log(yara_rule,1)
    file_name = md5_encode(str(int(time.time())))+".yara"
    fp = open(yara_dir+file_name,"wb+")
    fp.write(yara_rule)
    fp.close()
    print "success ext {},save in:{}".format(funcname,yara_dir+file_name)

# version_list = {
#     "Go-1.16":"67 6f 31 2e 31 36",
#     "Go-1.15":"67 6f 31 2e 31 35",
# }

# def get_version():
#     max_addr = idc.MaxEA()
#     for k,v in version_list.items():
#         if ida_search.find_binary(0, max_addr,v, 16, idc.SEARCH_DOWN) != idc.BADADDR:
#             return k
#     return False

def check_repeat():
    parser = plyara.Plyara()
    all_yara = os.listdir(yara_dir)
    if ".DS_Store" in all_yara:
        all_yara.remove(".DS_Store")
    # print all_yara
    for x in all_yara:
        # print yara_dir+x
        f = open(yara_dir+x,"r")
        yara_info = parser.parse_string(f.read())
        info = {}
        for x in yara_info[0]['metadata']:
            info.update(x)
        # print info
        f.close()
        parser.clear()
        if info['func_name']==funcname and info['go_arch']==go_arch and info['go_version']==go_version:
            return 0
    return 1

if __name__ == "__main__":

    funcname = "os_exec_Command"
    funcaddr = 0x00645E40
    go_arch = "Linux"
    go_version = "GO-1.14"

    print_banner()
    # current_version =  get_version()
    # print "[+] 当前Go版本检测为:%s"% current_version
    # yara_dir = os.path.split((os.path.abspath(__file__)))[0]+"/yara_rule_db/"+current_version+"/"
    # if os.path.exists(yara_dir)!=True:#确保目录存在
    #     os.mkdir(yara_dir)
    # print "[+] 函数识别yara路径为:%s"% yara_dir
    tool_path = os.path.split((os.path.abspath(__file__)))[0]
    yara_dir = tool_path+"/yara_rule_db/"
    # get_one_func_data(funcname,funcaddr)
    sign = check_repeat()
    if sign:
        get_one_func_data(funcname,funcaddr)
    else:
        print "规则已存在"
    # check_repeat()