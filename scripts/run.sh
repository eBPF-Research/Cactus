sudo sysctl -w net.ipv4.ip_forward=1
sudo chmod +x traffic-shuffler
sudo ./traffic-shuffler -f conf.yaml