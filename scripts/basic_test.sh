sudo sysctl -w net.ipv4.ip_forward=1
ti=100
echo "run traffic-shuffler for ${ti}s"
sudo timeout --preserve-status -s SIGINT 1m $ROOT_DIR/bin/traffic-shuffler -f $ROOT_DIR/scripts/conf.yaml -v