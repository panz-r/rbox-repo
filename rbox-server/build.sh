#!/bin/bash
set -e

cd "$(dirname "$0")"

RBOX_PROTO="$(pwd)/../rbox-protocol"
SHELLSPLIT="$(pwd)/../shellsplit"

export CGO_LDFLAGS="-L${RBOX_PROTO} -L${SHELLSPLIT} -lrbox_protocol -lshellsplit -lpthread -lm"
export CGO_CFLAGS="-I${RBOX_PROTO}/include -I${SHELLSPLIT}/include"

case "${1:-build}" in
clean)
	rm -f rbox-server
	;;
build)
	go build -tags cgo -o rbox-server .
	;;
*)
	echo "Usage: $0 {build|clean}"
	exit 1
	;;
esac