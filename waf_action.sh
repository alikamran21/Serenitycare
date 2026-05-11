#!/bin/bash
# /etc/nginx/waf_action.sh
# Triggered by ModSecurity Web Application Firewall.
# Logs SQLi attackers directly into the Phantasm-DB bypassing the backend.

# ModSecurity passes the attacker's IP via the REMOTE_ADDR environment variable
ATTACKER_IP="${REMOTE_ADDR:-127.0.0.1}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
REASON="WAF Hard Block: Critical SQL Injection Signature Detected"

# Database connection variables 
# (Update these to match the credentials in your docker-compose.yml)
DB_HOST="db"             # Assuming your database service is named 'db'
DB_USER="postgres"
DB_NAME="postgres"       # Or 'serenity' depending on your setup
export PGPASSWORD="your_database_password_here"

# 1. Insert the IP into the threat_actors table
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "
    INSERT INTO monitor.threat_actors (ip_address, reason, threat_level, flagged_at) 
    VALUES ('$ATTACKER_IP', '$REASON', 'critical', '$TIMESTAMP') 
    RETURNING threat_id;
" | while read THREAT_ID; do
    
    # 2. If we successfully got a Threat ID, insert a record into the forensic ledger
    if [ -n "$THREAT_ID" ]; then
        # Clean up whitespace from the returned ID
        THREAT_ID=$(echo $THREAT_ID | xargs)
        
        psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
            INSERT INTO monitor.forensic_ledger (threat_id, action_type, target_table, query_text, created_at)
            VALUES ($THREAT_ID, 'WAF_SQLI_BLOCK', 'NGINX_EDGE', 'Payload matched ModSecurity Rule 1001. Request dropped before reaching backend.', '$TIMESTAMP');
        "
    fi
done

exit 0