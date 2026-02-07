#!/bin/bash
echo "Starting server in background..."
/home/panz/osrc/lms-test/readonlybox/bin/readonlybox-server -tui &
SERVER_PID=$!
sleep 2

echo "Generating test commands..."
for i in {1..20}; do
    LD_PRELOAD=/home/panz/osrc/lms-test/readonlybox/bin/libreadonlybox_client.so echo "test command $i" >/dev/null 2>&1 &
    sleep 0.1
done

echo "Test commands sent. Check TUI scrolling (Ctrl+C to stop)"
wait $SERVER_PID
