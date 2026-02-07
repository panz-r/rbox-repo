#!/bin/bash

# Test script to generate many commands for scrolling test

echo "Testing scrolling with many commands..."

for i in {1..50}; do
    echo "Command $i"
    LD_PRELOAD=/home/panz/osrc/lms-test/readonlybox/bin/libreadonlybox_client.so ls -la /tmp 2>/dev/null &
    sleep 0.1
done

echo "Done generating commands. Check TUI scrolling."