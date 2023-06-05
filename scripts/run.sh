sudo sysctl -w net.ipv4.ip_forward=1
sudo chmod +x traffic-shuffler
# 超过2m，就终止进程，防止错误的程序影响网络
sudo timeout -s SIGINT 2m ./traffic-shuffler -f conf.yaml