#!/bin/bash
# Generate seed corpus for dfa_eval_fuzzer from existing test data

set -e

CORPUS_DIR="corpus/seed/dfa_eval"
TMP_DIR="corpus/tmp_commands"

mkdir -p "$CORPUS_DIR"
mkdir -p "$TMP_DIR"

echo "== Extracting commands from pattern files =="

# Extract commands from pattern files (lines like: [category] command pattern)
for pattern_file in ../patterns_*.txt ../test_group.txt; do
    if [ -f "$pattern_file" ]; then
        echo "Processing $pattern_file..."
        # Extract command patterns, removing category tags and arrows
        grep -E '^\s*\[.*\]\s+.+' "$pattern_file" | \
            sed -E 's/^\s*\[[^]]+\]\s+//; s/->.*$//' | \
            head -100 >> "$TMP_DIR/commands.txt"
    fi
done

# Also extract from readonlybox.dfa test data
if [ -f "../readonlybox.dfa" ]; then
    echo "Testing with readonlybox.dfa to generate valid commands..."
    # We can't extract commands from binary DFA, but we know some are valid
    echo "cat file.txt" >> "$TMP_DIR/commands.txt"
    echo "git log" >> "$TMP_DIR/commands.txt"
    echo "ps aux" >> "$TMP_DIR/commands.txt"
    echo "find . -name '*.txt'" >> "$TMP_DIR/commands.txt"
    echo "ls -la" >> "$TMP_DIR/commands.txt"
    echo "grep pattern file.txt" >> "$TMP_DIR/commands.txt"
    echo "df -h" >> "$TMP_DIR/commands.txt"
    echo "du -sh" >> "$TMP_DIR/commands.txt"
    echo "whoami" >> "$TMP_DIR/commands.txt"
    echo "date" >> "$TMP_DIR/commands.txt"
    echo "echo 'hello world'" >> "$TMP_DIR/commands.txt"
    echo "pwd" >> "$TMP_DIR/commands.txt"
fi

echo "== Adding edge cases =="
# Add known edge cases
cat >> "$TMP_DIR/commands.txt" << 'EOF'
# Empty and whitespace

#
#
#
a
ab
abc
abcd
abcde

# Very long command (but under 4096)
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Special characters
!
@
#
$
%
^
&
*
(
)
-
+
=
{
}
[
]
|
\
;
:
'
"
,
.
<

# Quoted strings
"quoted string"
'single quoted'
"with'both'types"
"escape\"quote"

# Escape sequences
\0
\\n
\\t
\\r

# Unicode (UTF-8)
é
ö
ü
你好
Мир

# Numbers
0
1
123
1234567890

# Paths with slashes
/etc/passwd
/var/log/syslog
./relative/path
../parent/path
./corpus/data/user

# Command with many arguments
a b c d e f g h i j k l m n o p q r s t u v w x y z
1 2 3 4 5 6 7 8 9 10

# Pipes and redirects
cat file.txt | grep pattern
ls | head -10
echo "test" > out.txt
cat < input.txt > output.txt
2>&1

# Complex combinations
git log --oneline --all | grep commit | head -20
find . -name "*.txt" -type f -exec cat {} \;
ps aux | grep python | awk '{print $2}' | xargs kill

# Invalid but interesting
rm -rf /
sudo reboot
dd if=/dev/zero of=/dev/sda
:(){ :|:& };:
EOF

# Remove comments and blank lines from commands.txt
sed -i '/^#/d; /^\s*$$/d' "$TMP_DIR/commands.txt"

# Count commands
TOTAL_COMMANDS=$(wc -l < "$TMP_DIR/commands.txt")
echo "Total commands to convert: $TOTAL_COMMANDS"

# Convert each command to a separate file in the corpus
echo "== Creating corpus files =="
count=0
while IFS= read -r cmd; do
    # Trim whitespace
    cmd="$(echo "$cmd" | sed 's/^[[:space:]]*//;s/[[:space:]]*$$//')"
    if [ -n "$cmd" ]; then
        printf "%s" "$cmd" > "$CORPUS_DIR/$(printf "%05d" $count)"
        count=$((count + 1))
    fi
done < "$TMP_DIR/commands.txt"

echo "Created $count corpus files in $CORPUS_DIR"

# Also create a dictionary with common tokens
echo "== Creating dictionary file =="
cat > cmd_dict.txt << 'EOF'
cat
grep
find
ls
ps
git
log
status
diff
show
file
df
du
whoami
date
echo
pwd
head
tail
sort
uniq
wc
awk
sed
cut
tr
split
cat
less
more
find
locate
whereis
which
type
file
stat
ls
dir
vdir
cd
pushd
popd
dirs
pwd
echo
printf
test
[
exit
return
set
unset
export
read
trap
kill
wait
jobs
fg
bg
disown
sudo
su
chmod
chown
chgrp
mv
cp
rm
mkdir
rmdir
ln
dd
tar
gzip
gunzip
bzip2
bunzip2
xz
unxz
zip
unzip
ssh
scp
rsync
curl
wget
ftp
sftp
telnet
nc
netcat
ping
traceroute
dig
nslookup
host
ifconfig
ip
route
netstat
ss
iptables
ufw
systemctl
service
journalctl
dmesg
ps
top
htop
atop
vmstat
iostat
mpstat
sar
free
vmstat
dmesg
tail
journalctl
syslog
log
messages
access
auth
kern
EOF

echo "Dictionary created with $(wc -l < cmd_dict.txt) entries"

# Cleanup temp dir
rm -rf "$TMP_DIR"

echo "== Done =="
echo "To run fuzzer: cd .. && make -C fuzz run-dfa"
echo "To run with dictionary: make -C fuzz run-dfa-dict"
