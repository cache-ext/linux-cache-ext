#!/bin/bash

set -e
set -x
set -o pipefail
set -u

DATA_DIR=$1
MM_H_PATH="$DATA_DIR/include/linux/mm.h"

for i in {1..5}; do
    make -C "$DATA_DIR" -j8
    touch "$MM_H_PATH"
done
