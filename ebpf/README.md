

## eBPF需要的头文件 (include目录的文件)   
从libbpf拉取的最新的头文件(支持CO-RE)：  
``` 
cd include
bash update.sh
```

在自己电脑上生成vmlinux.h：  
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_5_15_0.h

# 建立一个软连接，方便修改版本
ln -s vmlinux_5_15_0.h vmlinux.h
```

## 头文件引用说明
include中全部加到all.h了，因此外部的只需要引用all.h

### 启用CO-RE功能  
为了兼容不同kernel。所以用vm_linux.h，而不是用uapi.h。因此缺少的定义需要自己去重新定义。
目前CO-RE下都定义在tc_xdp_co_re.h中。  


### 不用CO-RE
