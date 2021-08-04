#coding:utf-8
# import idc
import sys
import getopt
import os
from capstone import *
# import ida_search
# from capstone import *

yara_rule_dir = {}

def print_banner():
    print(
    '''
 ____ _____           ____  _     _   _                   _     _     
| __ )_   _|         |  _ \(_)___| |_(_)_ __   __ _ _   _(_)___| |__  
|  _ \ | |    _____  | | | | / __| __| | '_ \ / _` | | | | / __| '_ \ 
| |_) || |   |_____| | |_| | \__ \ |_| | | | | (_| | |_| | \__ \ | | |
|____/ |_|           |____/|_|___/\__|_|_| |_|\__, |\__,_|_|___/_| |_|
                                              |___/                   
author:     萝卜
time:       2021.08.04  
contact:    pwntool@163.com 

识别结果如下所示：\n
''')

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

data_dir = "/Users/radish/go/demo/ext_func_bin/"
yara_dir = ""


def get_all_func_data():
    index = 0
    for func in idautils.Functions():
        # print func, idc.GetFunctionName(func) ,
        # print SegName(func)
        if SegName(func)!=".text":
            break
        func_name = idc.GetFunctionName(func)
        if len(func_name)>0x50:
            break
        # print len(func_name),
        func_start_addr = idc.GetFunctionAttr(func, FUNCATTR_START)
        func_end_addr = idc.GetFunctionAttr(func, FUNCATTR_END)
        # print "func info: func name-> %s start addr -> %08x, end start -> %08x" % (func_name,func_start_addr,func_end_addr)
        func_data = ""
        for x in range(func_start_addr,func_end_addr):
            tmp = ""
            tmp = "%02x" % (Byte(x))
            func_data += tmp
            # func_data += hex(Byte(x))[2:]
        # print func_data
        if func_data=="c3":
            break
        f = open(data_dir+fmt_name(func_name)+".bin","wb+")
        f.write(func_data.decode("hex"))
        f.close()

        # print func_data.encode("hex")
        index +=1
        # if index==1:
        #     break
    print "函数总数{}".format(index)



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
    yara_rule = '''rule checkfunc:%s {
meta:
    autor = "radish"
    func_name = "%s"
strings:
    $s1 = {%s}
condition:
    any of them
}
'''%(funcname,funcname,func_yara)
    # print_log(yara_rule,1)
    fp = open(yara_dir+funcname+".yara","wb+")
    fp.write(yara_rule)
    fp.close()
    # f = open(data_dir+fmt_name(funcname)+".bin","wb+")
    # f.write(func_data.decode("hex"))
    # f.close()
    print "success ext {}".format(funcname)

def scan_init():
    #把yara字典读取到内存中，
    index = 0
    yara_list = os.listdir(yara_dir)#确保yara_list里面必须都是yara文件，如果存在不是的，需要进行去除
    for x in yara_list:
        yara_rule_dir[str(index)]=yara_dir+x
        index += 1
    print yara_rule_dir

def scan_yara(bindata):
    rule = yara.compile(filepaths=yara_rule_dir)
    matches = rule.match(data=bindata)
    if len(matches) == 1:
        # print "-----------------------"
        # for match in matches:
        #     if match.strings[0][0] ==0:
        #         print match.rule,match.tags,match.strings

        return matches
    else:
        return 0

def recognition_function():
    #遍历IDA解析出来的函数进行yara匹配
    index = 0
    for func in idautils.Functions():
        # print func, idc.GetFunctionName(func) ,
        # print SegName(func)
        if SegName(func)!=".text":
            break
        func_name = idc.GetFunctionName(func)
        # if len(func_name)>0x30:
        #     break
        func_start_addr = idc.GetFunctionAttr(func, FUNCATTR_START)
        func_end_addr = idc.GetFunctionAttr(func, FUNCATTR_END)
        # print "func info: func name-> %s start addr -> %08x, end start -> %08x" % (func_name,func_start_addr,func_end_addr)
        func_data = ""
        for x in range(func_start_addr,func_end_addr):
            tmp = ""
            tmp = "%02x" % (Byte(x))
            func_data += tmp
            # func_data += hex(Byte(x))[2:]
        # print func_data
        m = scan_yara(func_data.decode("hex"))
        if m!=0:
            print "-------------------{}--------------------".format(func_name)
            for match in m:
                if match.strings[0][0] ==0:
                    # print match.tags,hex(func_start_addr)#,match.strings,match.rule,
                    print "地址为 %08x 的函数匹配到yara规则 %s" % (func_start_addr,match.tags)
        index+=1
    print "一共检测的函数总数为{}".format(index)

def scan_init_bak():
    #把所有yara字典读取到内存中，
    # index = 0
    # tool_path = os.path.split((os.path.abspath(__file__)))[0]
    # yara_version_list = os.listdir(tool_path+"/yara_rule_db/")
    # if ".DS_Store" in yara_version_list:
    #     yara_version_list.remove(".DS_Store")
    # for x in yara_version_list:
    #     yara_list = os.listdir(tool_path+"/yara_rule_db/"+x)
    #     for y in yara_list:
    #         yara_rule_dir[x+"_"+str(index)]=tool_path+"/yara_rule_db/"+x+"/"+y
    #         index+=1
    index = 0
    yara_path = os.path.split((os.path.abspath(__file__)))[0]+"/yara_rule_db/"
    yara_list = os.listdir(yara_path)
    if ".DS_Store" in yara_list:
        yara_list.remove(".DS_Store")
    for x in yara_list:
        yara_rule_dir[str(index)] = yara_path+x
        index+=1
    # print yara_rule_dir

    

    # print yara_rule_dir
    # yara_list = os.listdir(yara_dir)#确保yara_list里面必须都是yara文件，如果存在不是的，需要进行去除
    # for x in yara_list:
        # yara_rule_dir[str(index)]=yara_dir+x
        # index += 1

def scan_yara_bak(bindata):
    rule = yara.compile(filepaths=yara_rule_dir)
    matches = rule.match(data=bindata)
    if len(matches) > 0:
        # print "-----------------------"
        # for match in matches:
        #     if match.strings[0][0] ==0:
        #         print match.rule,match.tags,match.strings

        return matches
    else:
        return 0

def recognition_function_bak():
    #将.text段进行yara匹配，通过偏移得到函数地址
    seg_text_start = get_segm_by_sel(selector_by_name(".text"))#直接获取 .text 段地址
    seg_text_end = SegEnd(seg_text_start)
    bin_data = ""
    for x in range(seg_text_start,seg_text_end):
        bin_data += chr(Byte(x))
        # print Byte(x)
    m = scan_yara_bak(bin_data)
    if m!=0:
        for match in m:
            print "地址为 %08x 的函数识别到已有规则  系统架构:%s\tGo版本:%s\t函数名:%s" % (match.strings[0][0]+seg_text_start,match.meta['go_arch'],match.meta['go_version'],match.meta['func_name'])
            # print match.tags,
            # if match.strings[0][0] ==0:
                # print match.tags,hex(func_start_addr)#,match.strings,match.rule,
                # print "地址为 %08x 的函数匹配到yara规则 %s" % (func_start_addr,match.tags)
    else:
        print "no"
    #     index+=1
version_list = {
    "GO-1.16":"67 6f 31 2e 31 36",
    "GO-1.15":"67 6f 31 2e 31 35",
}

def get_version():
    max_addr = idc.MaxEA()
    for k,v in version_list.items():
        if ida_search.find_binary(0, max_addr,v, 16, idc.SEARCH_DOWN) != idc.BADADDR:
            return k
    return False

if __name__ == "__main__":
    print_banner()
    # current_version =  get_version()
    # print "[+] 当前Go版本检测为:%s"% current_version
    # yara_dir = os.path.split((os.path.abspath(__file__)))[0]+"/yara_rule_db/"+current_version+"/"
    # print "[+] 函数识别yara路径为:%s"% yara_dir
    # scan_init()
    # recognition_function()
    scan_init_bak()
    recognition_function_bak()