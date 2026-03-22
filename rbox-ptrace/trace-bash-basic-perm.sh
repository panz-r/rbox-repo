./readonlybox-ptrace --no-network --memory-limit 1G --landlock-paths /w/rbox-repo:rwx,/usr/bin:rx,/lib64:rx,/usr/lib:rx,/etc:ro,/tmp:rw,/proc:ro  -- bash
