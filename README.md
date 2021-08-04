# BT_tool
在恶意样本分析中，基于二进制来识别Go函数

基于`gopclntab`段来恢复函数符号虽然方便，但是如果这个段没有了，岂不是不能恢复了，而且这种方法受版本限制。基于二进制来识别Go函数是就防止黑客把`gopclntab`段的数据修改或者删除就不能够进行恢复函数名。缺点是能够识别出来函数的多少取决于`yara`规则的多少

# 使用方法
## 识别函数
ida中运行BT_tools.py，进行函数识别
```bash

 ____ _____           ____  _     _   _                   _     _     
| __ )_   _|         |  _ \(_)___| |_(_)_ __   __ _ _   _(_)___| |__  
|  _ \ | |    _____  | | | | / __| __| | '_ \ / _` | | | | / __| '_ \ 
| |_) || |   |_____| | |_| | \__ \ |_| | | | | (_| | |_| | \__ \ | | |
|____/ |_|           |____/|_|___/\__|_|_| |_|\__, |\__,_|_|___/_| |_|
                                              |___/                   
author:     萝卜
time:       2021.08.04  
contact:    pwntool@163.com 

识别结果如下所示：


地址为 004d43c0 的函数识别到已有规则  系统架构:Linux	Go版本:GO-1.16	函数名:fmt_Fprintln
地址为 00643180 的函数识别到已有规则  系统架构:Linux	Go版本:GO-1.16	函数名:os_exec___Cmd__Output
地址为 005fc5c0 的函数识别到已有规则  系统架构:Linux	Go版本:GO-1.16	函数名:net_http___Client__Post
地址为 005fab80 的函数识别到已有规则  系统架构:Linux	Go版本:GO-1.16	函数名:net_http___Client__Get
```

## 添加函数Yara规则

修改`BT_add_yara.py`中配置项：
```python
    funcname = "os_exec_Command"
    funcaddr = 0x00645E40
    go_arch = "Linux"
    go_version = "GO-1.14"
```
ida中运行即可

## 列出支持识别的Yara规则
终端运行`python BT_show_all_yara.py`，如下所示：

```bash
~/go/RT
❯ python show_all_yara.py

 ____ _____           ____  _                    __   __
| __ )_   _|         / ___|| |__   _____      __ \ \ / /_ _ _ __ __ _
|  _ \ | |    _____  \___ \| '_ \ / _ \ \ /\ / /  \ V / _` | '__/ _` |
| |_) || |   |_____|  ___) | | | | (_) \ V  V /    | | (_| | | | (_| |
|____/ |_|           |____/|_| |_|\___/ \_/\_/     |_|\__,_|_|  \__,_|


author:     萝卜
time:       2021.08.04
contact:    pwntool@163.com


Go版本:GO-1.14, 系统架构:Linux, 函数名:net_http___Client__Post
Go版本:GO-1.14, 系统架构:Linux, 函数名:os_exec_Command
Go版本:GO-1.16, 系统架构:Linux, 函数名:os_exec___Cmd__Output
Go版本:GO-1.16, 系统架构:Linux, 函数名:fmt_Fprintln
Go版本:GO-1.16, 系统架构:Linux, 函数名:net_http___Client__Get
Go版本:GO-1.16, 系统架构:Linux, 函数名:net_http___Client__Post
Go版本:GO-1.14, 系统架构:Linux, 函数名:net_http___Client__Get
```
