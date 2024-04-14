#!/bin/bash

echo "Enter to start..."
read

cgexec -g memory:cache_ext_1 ./test_app.py file1 &
pid1=$!

cgexec -g memory:cache_ext_2 ./test_app.py file2 &
pid2=$!

echo "Enter to finish..."
read

kill $pid1 $pid2

