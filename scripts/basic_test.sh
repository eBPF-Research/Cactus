sudo sysctl -w net.ipv4.ip_forward=1
sudo timeout --preserve-status -s SIGINT 2s $ROOT_DIR/bin/traffic-shuffler -f $ROOT_DIR/scripts/conf.yaml -v