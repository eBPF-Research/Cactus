self_path=`readlink -f "${BASH_SOURCE:-$0}"`
self_dir=`dirname $self_path`

export ROOT_DIR=`realpath $self_dir/../`
# echo "Use root dir: "$ROOT_DIR