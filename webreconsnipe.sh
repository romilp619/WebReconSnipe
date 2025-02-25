#!/bin/bash

DEFAULT_OUTPUT_DIR="recon_output"
OUTPUT_DIR=""
SKIP_TRUFFLEHOG=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) TARGET="$2"; shift ;;
        -f|--file) DOMAIN_FILE="$2"; shift ;;
        -o|--output) OUTPUT_DIR="$2"; shift ;;
        --skip-trufflehog) SKIP_TRUFFLEHOG=true ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Set default output directory if not provided
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
fi

# Check if either domain or file is provided
if [ -z "$TARGET" ] && [ -z "$DOMAIN_FILE" ]; then
    echo "Usage: $0 [-d|--domain <domain>] [-f|--file <domains_file>] [-o|--output <output_dir>] [--skip-trufflehog]"
    echo "  -d/--domain: Single target domain (e.g., https://www.tataplay.com)"
    echo "  -f/--file: File with multiple domains (one per line)"
    echo "  -o/--output: Output directory (default: recon_output)"
    echo "  --skip-trufflehog: Skip TruffleHog scan"
    exit 1
fi

# Handle multiple domains from file
if [ -n "$DOMAIN_FILE" ]; then
    if [ ! -f "$DOMAIN_FILE" ]; then
        echo "[!] File not found: $DOMAIN_FILE"
        exit 1
    fi
    mapfile -t TARGETS < "$DOMAIN_FILE"
else
    TARGETS=("$TARGET")
fi

# Setup output directory
mkdir -p "$OUTPUT_DIR"

# Process each target domain
for TARGET in "${TARGETS[@]}"; do
    if [ -z "$TARGET" ]; then
        echo "[!] Skipping empty target"
        continue
    fi

    echo "[+] Processing target: $TARGET"

    # Step 1: Fetch archived URLs
    echo "[+] Fetching archived URLs for $TARGET..."
    echo "$TARGET" | waybackurls | tee -a "$OUTPUT_DIR/all_urls.txt"

    # Step 2: Deduplicate URLs
    echo "[+] Deduplicating URLs..."
    cat "$OUTPUT_DIR/all_urls.txt" | sort -u > "$OUTPUT_DIR/clean_urls.txt"

    # Step 3: Filter for sensitive files and keywords
    echo "[+] Filtering for sensitive files and keywords..."
    cat "$OUTPUT_DIR/clean_urls.txt" | grep -E -i "(\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.env|\.ini|\.properties|\.sqlite|\.sqlite3|\.db3|\.dump|\.bk|\.key|\.crt|\.pem|\.sh|\.bat|\.war|\.ear|\.rst|\.tmp|\.session|\.html|\.js|\.out|\.p12|\.conf|\.mysql|\.mem|\.exe|\.dll|\.xsl|\.nz|\.data|\.graphql|\.token|\.php|\.asp|\.aspx|\.jsp|\.git|\.svn|\.htaccess|\.htpasswd|backup|config|admin|test|dev|staging|api_key|secret_key|password|passwd|credential|private|key=|token=)" > "$OUTPUT_DIR/filtered_urls.txt"

    # Step 4: Extract parameters with gf
    echo "[+] Extracting potential secrets and vulnerabilities..."
    cat "$OUTPUT_DIR/filtered_urls.txt" | gf secrets | tee -a "$OUTPUT_DIR/secrets_urls.txt"
    cat "$OUTPUT_DIR/filtered_urls.txt" | gf sqli | tee -a "$OUTPUT_DIR/sqli_urls.txt"
    cat "$OUTPUT_DIR/filtered_urls.txt" | gf xss | tee -a "$OUTPUT_DIR/xss_urls.txt"
    cat "$OUTPUT_DIR/filtered_urls.txt" | gf idor | tee -a "$OUTPUT_DIR/idor.txt"

    # Step 6: Validate live endpoints with httpx-toolkit
    echo "[+] Checking live endpoints with httpx-toolkit..."
    cat "$OUTPUT_DIR/filtered_urls.txt" | httpx-toolkit -silent -sc -mc 200 -o "$OUTPUT_DIR/live_urls.txt"

    # Step 5: Scan content for secrets with trufflehog (skippable)
    if [ "$SKIP_TRUFFLEHOG" == "false" ]; then
        echo "[+] Scanning content for secrets with TruffleHog..."
        cat "$OUTPUT_DIR/filtered_urls.txt" | xargs -P 1 -I {} sh -c 'tempfile=$(mktemp); echo "Fetching {}" >&2; curl -s -L "{}" -f --retry 2 --max-time 10 > "$tempfile"; if [ $? -eq 0 ] && [ -s "$tempfile" ]; then echo "Scanning {}" >&2; trufflehog filesystem "$tempfile" --no-verification --no-update --json --detector-timeout=30s; else echo "Skipped {} (no content or curl failed)" >&2; fi; rm -f "$tempfile"' >> "$OUTPUT_DIR/secrets_found.txt"
    else
        echo "[+] Skipping TruffleHog scan for $TARGET..."
        touch "$OUTPUT_DIR/secrets_found.txt"
    fi
done

# Step 7: Combine results
echo "[+] Generating final report..."
cat "$OUTPUT_DIR/live_urls.txt" "$OUTPUT_DIR/secrets_urls.txt" "$OUTPUT_DIR/sqli_urls.txt" "$OUTPUT_DIR/xss_urls.txt" "$OUTPUT_DIR/idor.txt" | sort -u > "$OUTPUT_DIR/final_report.txt"

echo "[+] Done! Check $OUTPUT_DIR/final_report.txt for results."
