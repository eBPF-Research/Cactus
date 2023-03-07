

## eBPF需要的头文件 (include目录的文件)   
从libbpf拉取的最新的头文件(支持CO-RE)：  
``` 
bash update.sh
```

在自己电脑上生成vmlinux.h：  
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_5_15_0.h
```

全部加到all.h中。  

## 启用CO-RE功能  
为了兼容不同kernel。所以用vm_linux.h，而不是用uapi.h。因此缺少的定义需要自己去重新定义。
