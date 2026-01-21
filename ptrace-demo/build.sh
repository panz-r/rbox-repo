#!/bin/bash
# build.sh
set -e

# Create directories
sudo mkdir -p /usr/lib/security_wrapper

# Build the tracer
gcc -o security_tracer security_tracer.c -Wall -O2

# Build the advanced placeholder
gcc -o advanced_placeholder advanced_placeholder.c -Wall -O2
sudo cp advanced_placeholder /usr/lib/security_wrapper/placeholder
sudo chmod 0755 /usr/lib/security_wrapper/placeholder

# Or create simple shell script placeholder
cat > /tmp/placeholder.sh << 'EOF'
#!/bin/bash
# Simple placeholder that outputs to stderr and exits with success
if [[ "$1" == "--denied" ]]; then
    shift
    if [[ "$1" == --cmd=* ]]; then
        CMD="${1#--cmd=}"
        shift
        echo "Permission denied: Command '$CMD' blocked" >&2
        # Simulate empty successful output
        exit 0
    fi
fi
exit 0
EOF

sudo cp /tmp/placeholder.sh /usr/lib/security_wrapper/placeholder.sh
sudo chmod 0755 /usr/lib/security_wrapper/placeholder.sh
sudo ln -sf /usr/lib/security_wrapper/placeholder.sh /usr/lib/security_wrapper/placeholder

echo "Build complete!"
echo "Usage: ./security_tracer <command> [args...]"
echo "Example: ./security_tracer /bin/cat /etc/passwd"
