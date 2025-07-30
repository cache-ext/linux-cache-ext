#!/bin/bash

set -x
set -e
set -o pipefail


cd /mydata
rclone copy --progress --transfers 64 --checkers 64 twitter_traces/ b2:twitter-traces
rclone check --progress --transfers 64 --checkers 64 twitter_traces/ b2:twitter-traces


for cluster in 4 34 35 17 18 19 24 52; do
    rclone copy --progress --transfers 64 --checkers 64 leveldb_twitter_cluster${cluster}_db/ b2:leveldb-twitter-cluster${cluster}-db
    rclone check --progress --transfers 64 --checkers 64 leveldb_twitter_cluster${cluster}_db/ b2:leveldb-twitter-cluster${cluster}-db
done