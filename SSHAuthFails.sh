#!/bin/bash
# deb / ubuntu distros
LOG_FILE="/var/log/auth.log"
OUTPUT_FILE="failed_ssh_attempts.csv"

echo "timestamp,user,ip_address,failure_type" > "$OUTPUT_FILE"

grep "Failed password" "$LOG_FILE" 2>/dev/null | \
awk '
/Failed password/ {
    # Extract timestamp from brackets
    match($0, /\[([^\]]*)\]/)
    ts = substr($0, RSTART+1, RLENGTH-2)
    
    # Find IP address (typically the last IP-like field)
    ip = ""
    for(i=NF; i>=1; i--) {
        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            ip = $i
            break
        }
    }
    
    # Extract username after "for" keyword
    user = ""
    for(i=1; i<=NF; i++) {
        if ($i == "for") {
            user = $(i+1)
            break
        }
    }
    
    print ts "," user "," ip ",password"
}' >> "$OUTPUT_FILE"

# Summary statistics
echo ""
echo "=== SSH Login Failure Report ===" 
echo "Date: $(date)"
echo "Total failed attempts: $(grep -c "Failed password" "$LOG_FILE")"
echo ""
echo "Top 10 IP addresses with failures:"
awk -F',' 'NR>1 {print $3}' "$OUTPUT_FILE" | sort | uniq -c | sort -rn | head -10
