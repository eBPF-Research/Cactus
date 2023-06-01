sudo sysctl -w net.ipv4.ip_forward=1
$ROOT_DIR/bin/traffic-shuffler -f $ROOT_DIR/scripts/conf.yaml -v