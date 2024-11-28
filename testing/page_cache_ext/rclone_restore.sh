#!/bin/bash

set -x
set -e
set -o pipefail


cd /mydata
rclone copy --progress --transfers 64 --checkers 64 b2:twitter-traces twitter_traces/
rclone check --progress --transfers 64 --checkers 64 b2:twitter-traces twitter_traces/


for cluster in 4 34 35 17 18 19 24 52; do
    rclone copy --progress --transfers 64 --checkers 64 b2:leveldb-twitter-cluster${cluster}-db leveldb_twitter_cluster${cluster}_db/
    rclone check --progress --transfers 64 --checkers 64 b2:leveldb-twitter-cluster${cluster}-db leveldb_twitter_cluster${cluster}_db/
done