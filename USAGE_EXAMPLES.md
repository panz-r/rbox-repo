# ReadOnlyBox Usage Examples 📚

This document provides comprehensive usage examples for ReadOnlyBox, demonstrating both safe operations and security features.

## 📋 Table of Contents

- [Basic Usage](#-basic-usage)
- [System Monitoring](#-system-monitoring)
- [File Exploration](#-file-exploration)
- [Git Operations](#-git-operations)
- [Search and Text Processing](#-search-and-text-processing)
- [Security Examples](#-security-examples)
- [Advanced Usage](#-advanced-usage)
- [Comparison with Original Commands](#-comparison-with-original-commands)

## 🚀 Basic Usage

### Show Help
```bash
# Show all available commands
readonlybox

# Show version information for a specific command
readonlybox git --version
readonlybox ps --version
```

### Command Structure
```bash
# Basic structure: readonlybox <command> [arguments...]
readonlybox ls -la
readonlybox df -h
readonlybox uname -a
```

## 🖥️ System Monitoring

### Process Monitoring
```bash
# List all processes
readonlybox ps aux

# List processes in a tree format
readonlybox ps -ef --forest

# Find processes by name
readonlybox ps aux | readonlybox grep nginx

# Show process information for specific PID
readonlybox ps -p 1 -f
```

### Disk Usage
```bash
# Show disk space usage
readonlybox df -h

# Show disk space for specific filesystem
readonlybox df -h /

# Show inode usage
readonlybox df -i

# Show disk usage by directory
readonlybox du -sh /home
readonlybox du -h --max-depth=1 /var
```

### System Information
```bash
# Show system information
readonlybox uname -a

# Show kernel version
readonlybox uname -r

# Show hardware information
readonlybox uname -m

# Show all system info
readonlybox uname -a
```

## 📁 File Exploration

### Directory Listing
```bash
# List files in current directory
readonlybox ls

# List files with details
readonlybox ls -la

# List files with human-readable sizes
readonlybox ls -lh

# List files recursively
readonlybox ls -R
```

### File Viewing
```bash
# View file contents
readonlybox cat /etc/passwd

# View first 10 lines of a file
readonlybox head -n 10 /var/log/syslog

# View last 10 lines of a file
readonlybox tail -n 10 /var/log/syslog

# Follow a log file (read-only)
readonlybox tail -f /var/log/syslog
```

### File Searching
```bash
# Find files by name
readonlybox find /home -name "*.txt"

# Find files by type
readonlybox find /etc -type f -name "*.conf"

# Find files by size
readonlybox find /var -size +10M

# Find files by modification time
readonlybox find /home -mtime -7

# Find files with safe options
readonlybox find . -name "*.go" -type f
```

### File Content Searching
```bash
# Search for text in files
readonlybox grep "error" /var/log/syslog

# Recursive search
readonlybox grep -r "package main" .

# Case-insensitive search
readonlybox grep -i "warning" /var/log/syslog

# Search with context
readonlybox grep -A 3 -B 3 "exception" /var/log/syslog
```

## 🗃️ Git Operations

### Repository Inspection
```bash
# Show git version
readonlybox git --version

# Show commit history
readonlybox git log
readonlybox git log --oneline
readonlybox git log --graph --oneline --decorate

# Show commit details
readonlybox git show HEAD
readonlybox git show abc1234
```

### Repository Status
```bash
# Show repository status (read-only)
readonlybox git status

# Show branch information
readonlybox git branch -a
readonlybox git branch -v

# Show remote information
readonlybox git remote -v
```

### Code Inspection
```bash
# Show file changes
readonlybox git diff
readonlybox git diff HEAD~1

# Show file blame
readonlybox git blame README.md

# Show file content from git
readonlybox git show HEAD:README.md
```

### Configuration (Read-Only)
```bash
# List git configuration
readonlybox git config --list
readonlybox git config --global --list

# Get specific configuration
readonlybox git config user.name
readonlybox git config user.email
```

## 🔍 Search and Text Processing

### Text Processing
```bash
# Count lines, words, characters
readonlybox wc README.md
readonlybox wc -l *.go
readonlybox wc -w *.md

# Sort file contents
readonlybox sort names.txt
readonlybox sort -r names.txt
readonlybox sort -n numbers.txt

# Text substitution (read-only)
readonlybox sed 's/old/new/g' input.txt
readonlybox sed -i '' 's/foo/bar/' file.txt  # This would be BLOCKED
```

### Advanced Searching
```bash
# Find and count occurrences
readonlybox grep -c "pattern" file.txt

# Search multiple files
readonlybox grep "main" *.go

# Search with regular expressions
readonlybox grep -E "^[A-Z]" file.txt

# Search and show line numbers
readonlybox grep -n "function" script.sh
```

## 🛡️ Security Examples

### Blocked Operations
```bash
# ❌ BLOCKED: Git write operations
readonlybox git add .
# Error: write operation not allowed

readonlybox git commit -m "test"
# Error: write operation not allowed

readonlybox git push origin main
# Error: write operation not allowed

# ❌ BLOCKED: Dangerous find options
readonlybox find . -exec rm {} \;
# Error: can execute commands

readonlybox find . -delete
# Error: can delete files

# ❌ BLOCKED: Command injection attempts
readonlybox ps "`rm -rf /`"
# Error: contains potential command injection characters

readonlybox ls "$(whoami)"
# Error: contains potential command injection characters

# ❌ BLOCKED: Suspiciously long arguments
readonlybox ps $(python3 -c 'print("a"*51)')
# Error: suspiciously long option
```

### Allowed Operations
```bash
# ✅ ALLOWED: Safe git operations
readonlybox git log
readonlybox git show
readonlybox git status
readonlybox git diff

# ✅ ALLOWED: Safe find operations
readonlybox find . -name "*.go"
readonlybox find . -type f
readonlybox find . -size +1M

# ✅ ALLOWED: Normal command usage
readonlybox ps aux
readonlybox ls -la
readonlybox cat /etc/passwd
readonlybox df -h
```

## 🚀 Advanced Usage

### Command Chaining
```bash
# Chain multiple read-only commands
readonlybox find . -name "*.go" | readonlybox wc -l

readonlybox ps aux | readonlybox grep nginx | readonlybox wc -l

readonlybox cat /var/log/syslog | readonlybox grep error | readonlybox head -5
```

### Process Monitoring
```bash
# Monitor processes safely
readonlybox ps aux --sort=-%cpu | readonlybox head -5

readonlybox ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | readonlybox head

# Find processes by user
readonlybox ps -u root
readonlybox ps -U root -u root u
```

### Disk Analysis
```bash
# Analyze disk usage
readonlybox df -h | readonlybox grep -v tmpfs

readonlybox du -sh /* | readonlybox sort -h

readonlybox find /var -type f -size +100M | readonlybox xargs readonlybox ls -lh
```

### System Information
```bash
# Get comprehensive system info
readonlybox uname -a
readonlybox cat /etc/os-release
readonlybox cat /proc/cpuinfo | readonlybox head -5
readonlybox cat /proc/meminfo | readonlybox head -3
```

## 🔄 Comparison with Original Commands

### ReadOnlyBox vs Original Commands

| Task | Original Command | ReadOnlyBox Equivalent |
|------|------------------|-----------------------|
| List processes | `ps aux` | `readonlybox ps aux` |
| Show disk space | `df -h` | `readonlybox df -h` |
| List files | `ls -la` | `readonlybox ls -la` |
| View file | `cat file.txt` | `readonlybox cat file.txt` |
| Search files | `find . -name "*.txt"` | `readonlybox find . -name "*.txt"` |
| Git log | `git log` | `readonlybox git log` |
| Grep search | `grep "text" file` | `readonlybox grep "text" file` |
| System info | `uname -a` | `readonlybox uname -a` |

### What's Different

```bash
# ❌ This would work with original git but is blocked by ReadOnlyBox
git add .
readonlybox git add .  # BLOCKED

# ❌ This would work with original find but is blocked by ReadOnlyBox
find . -exec rm {} \;
readonlybox find . -exec rm {} \;  # BLOCKED

# ✅ These work the same in both
ls -la
readonlybox ls -la

cat /etc/passwd
readonlybox cat /etc/passwd
```

## 🎯 Best Practices

### Safe Usage Patterns
```bash
# Always use readonlybox for system exploration
readonlybox ps aux
readonlybox find /home -name "*.txt"
readonlybox git log --oneline

# Chain commands for powerful read-only analysis
readonlybox find . -name "*.log" | readonlybox xargs readonlybox ls -lh

# Use for security audits
readonlybox ps aux | readonlybox grep -v "^root"
readonlybox find /etc -type f -perm -4000
```

### What to Avoid
```bash
# ❌ Don't try to bypass security
readonlybox bash -c "rm -rf /"
# This will be blocked by security validation

# ❌ Don't use command substitution
readonlybox ls $(whoami)
# This will be blocked as potential injection

# ❌ Don't use very long arguments
readonlybox ps $(python3 -c 'print("a"*100)')
# This will be blocked as suspicious
```

## 📚 Reference

### All Available Commands

Run `readonlybox` without arguments to see the complete list of available commands.

### Getting Help

```bash
# Show all commands
readonlybox

# Get help for specific command
readonlybox git --help
readonlybox find --help
readonlybox ps --help
```

### Exit Codes

- `0`: Success
- `1`: Command not found or security violation
- Other: Underlying command's exit code

## 🎉 Conclusion

ReadOnlyBox provides a **safe, read-only environment** for system exploration while maintaining the familiar interface of standard Linux commands. Use it for:

- **Security audits**
- **Forensic analysis**
- **Restricted environments**
- **Education and training**
- **Safe system exploration**

**Explore freely, stay secure! 🔒**