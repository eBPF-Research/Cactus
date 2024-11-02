
This is the code for the paper `Cactus: Obfuscating Bidirectional Encrypted TCP Traffic at the Client Side`. We provide the tool `eBPF-Traffic-Shuffler`, which implements the Cactus system described in our paper.  

If you want to use our tool in your paper, you can cite it with the following bibtex.
```
@ARTICLE{10634310,
  author={Xie, Renjie and Cao, Jiahao and Zhu, Yuxi and Zhang, Yixiang and He, Yi and Peng, Hanyi and Wang, Yixiao and Xu, Mingwei and Sun, Kun and Dong, Enhuan and Li, Qi and Zhang, Menghao and Li, Jiang},
  journal={IEEE Transactions on Information Forensics and Security (TIFS)}, 
  title={Cactus: Obfuscating Bidirectional Encrypted TCP Traffic at Client Side}, 
  year={2024},
  volume={19},
  number={},
  pages={7659-7673},
  keywords={Cryptography;Protocols;TCP;Servers;Semantics;Fingerprint recognition;Uplink;Encrypted TCP traffic;traffic analysis attacks;traffic obfuscation},
  doi={10.1109/TIFS.2024.3442530}}
```


## eBPF Traffic Shuffler
利用eBPF修改TLS包的传播，实现对加密流的识别的防御。  

[![Go eBPF CI](https://github.com/eBPF-Research/eBPF-Traffic-Shuffler/actions/workflows/build.yml/badge.svg?branch=master&event=push)](https://github.com/eBPF-Research/eBPF-Traffic-Shuffler/actions/workflows/build.yml)

### 开发说明
项目结构遵循[Go标准项目布局](https://dev.to/jinxankit/go-project-structure-and-guidelines-4ccm), 其文件如下：
```
$ tree -L 1 
.
├── bin  		# 编译后的可执行文件	
├── cmd			# 若干个go主程序 (main.go)
├── docs		# 开发文档
├── ebpf		# eBPF程序
├── go.mod		# go 工程文件
├── go.sum		# go 依赖库版本锁定
├── Makefile
├── pkg			# 项目主要代码
├── README.md
├── scripts		# 启动和测试脚本
└── tools		# 测试程序
```

#### 编译说明  
1. 安装项目依赖库  
```
sudo apt install clang
go mod tidy
```

2. 编译测试项目
```
# 编译
make 

# 基本测试  
$ sudo make run
023/03/07 12:30:37 [LOG]             node-10627   [000] d.... 56291.786582: bpf_trace_printk: (classifier/one) new packet captured (TC)
```

开发Notes:   
1. ebpf依赖的头文件      
依赖uapi。需要用户安装对应版本header，参考：ebpf-manager  
https://github.com/DataDog/ebpf-manager/blob/main/examples/include/kernel.h



为了支持kernel 5.4，不使用CO-RE (undefine USE_CO_RE)。使用本地的uapi和linux header。


2. 加载的ebpf程序  
ebpf-manager会将代码中带有SEC(tc/xdp)都自动installed（但是没有attach），
因此最好把xdp_op/tc_op中没用到的SEC注释了，免得加载过程中verifier报错。
