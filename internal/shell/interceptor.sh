#!/bin/bash
# readonlybox command interceptor - sourced by bash before each command

# Only intercept if we're in readonlybox shell mode
if [[ "$READONLYBOX_ACTIVE" != "1" ]]; then
    return 0
fi

# Store the original command for readonlybox processing
readonlybox_original_cmd="$BASH_COMMAND"

# Extract the command name (first word)
readonlybox_cmd_name=""
if [[ -n "$READONLYBOX_ORIGINAL_ARGS" ]]; then
    readonlybox_cmd_name="$READONLYBOX_ORIGINAL_ARGS"
else
    readonlybox_cmd_name=$(echo "$BASH_COMMAND" | awk '{print $1}')
fi

# Skip if no command or if it's a shell builtin we want to allow
case "$readonlybox_cmd_name" in
    cd|pushd|popd|export|unset|alias|unalias|source|.|break|continue|return|exit)
        return 0
        ;;
esac

# Skip empty commands
if [[ -z "$readonlybox_cmd_name" ]]; then
    return 0
fi

# Check if the command might modify files (heuristics)
readonlybox_might_write=0
if echo "$BASH_COMMAND" | grep -qE '(>|>>|<|>|\\|tee|dd|mv|cp|rm|mkdir|touch|sed\ -i|awk\s*\{.*\}|\.|\[\[)'; then
    readonlybox_might_write=1
fi

# For now, log the command (in real implementation, would pipe to readonlybox)
if [[ "$READONLYBOX_DEBUG" == "1" ]]; then
    echo "[readonlybox] intercepted: $BASH_COMMAND" >&2
fi
