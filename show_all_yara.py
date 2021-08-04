#coding:utf-8
import os
import plyara
yara_dir = ""
def print_banner():
    print(
    '''
 ____ _____           ____  _                    __   __              
| __ )_   _|         / ___|| |__   _____      __ \ \ / /_ _ _ __ __ _ 
|  _ \ | |    _____  \___ \| '_ \ / _ \ \ /\ / /  \ V / _` | '__/ _` |
| |_) || |   |_____|  ___) | | | | (_) \ V  V /    | | (_| | | | (_| |
|____/ |_|           |____/|_| |_|\___/ \_/\_/     |_|\__,_|_|  \__,_|
                                                                      

author:     萝卜
time:       2021.08.04  
contact:    pwntool@163.com 

''')
def show_yara():
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
        print "Go版本:{}, 系统架构:{}, 函数名:{}".format(info['go_version'],info['go_arch'],info['func_name'])
        f.close()
        parser.clear()

if __name__ == "__main__":
    print_banner()
    tool_path = os.path.split((os.path.abspath(__file__)))[0]
    yara_dir = tool_path+"/yara_rule_db/"
    show_yara()