#!/bin/bash

# ReconPro - Advanced Reconnaissance Framework v3.0
# Complete version with all missing components from reconftw

# Configuration
TARGET=$1
WORKSPACE="./scans/$TARGET"
TOOLS_DIR="./tools"
WORDLISTS_DIR="./wordlists"
THREADS=100
TIMEOUT=15
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialize workspace
mkdir -p $WORKSPACE/{subdomains,urls,js,api,cloud,auth,workflows,results,ports,headers,params,tech,secrets,graphs,dependencies,endpoints,cors,debug}

# Banner
echo -e "${CYAN}"
echo "  ____                              ____  "
echo " |  _ \ ___  ___ _ __ _ __  _   _  |  _ \ ___  _ __ "
echo " | |_) / _ \/ __| '__| '_ \| | | | | |_) / _ \| '__|"
echo " |  _ <  __/ (__| |  | |_) | |_| | |  __/ (_) | |   "
echo " |_| \_\___|\___|_|  | .__/ \__, | |_|   \___/|_|   "
echo "                     |_|    |___/                   "
echo -e "${NC}"
echo -e "${GREEN}ReconPro v3.0 - Advanced Reconnaissance Framework${NC}"
echo -e "${YELLOW}Target: $TARGET${NC}"
echo -e "${BLUE}Workspace: $WORKSPACE${NC}"

# Dependency check
check_dependencies() {
    echo -e "${YELLOW}[+] Checking dependencies...${NC}"
    local deps=("subfinder" "assetfinder" "amass" "httpx" "nuclei" "katana" "gau" "waybackurls" "dnsx" "naabu" "subjs" "jq" "git")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${RED}[ERROR] $dep not found${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
}

# Phase 1: Comprehensive Subdomain Discovery
subdomain_discovery() {
    echo -e "\n${YELLOW}[PHASE 1] Comprehensive Subdomain Discovery${NC}"
    
    # Passive enumeration
    echo -e "${BLUE}[+] Running passive subdomain discovery...${NC}"
    subfinder -d $TARGET -silent -t $THREADS > $WORKSPACE/subdomains/subfinder.txt
    assetfinder -subs-only $TARGET > $WORKSPACE/subdomains/assetfinder.txt
    amass enum -passive -d $TARGET -o $WORKSPACE/subdomains/amass_passive.txt
    
    # Certificate transparency
    echo -e "${BLUE}[+] Checking certificate transparency...${NC}"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > $WORKSPACE/subdomains/cert_sh.txt
    
    # DNS bruteforce
    echo -e "${BLUE}[+] DNS bruteforcing...${NC}"
    puredns bruteforce $WORDLISTS_DIR/subdomains.txt $TARGET --resolvers $WORDLISTS_DIR/resolvers.txt > $WORKSPACE/subdomains/dns_brute.txt 2>/dev/null
    
    # Combine all subdomains
    cat $WORKSPACE/subdomains/*.txt | sort -u > $WORKSPACE/subdomains/all_subs.txt
    
    # Resolve to IPs
    echo -e "${BLUE}[+] Resolving subdomains to IPs...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | dnsx -silent -a -resp -o $WORKSPACE/subdomains/resolved_ips.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l) subdomains${NC}"
}

# Phase 2: Advanced Content Discovery
content_discovery() {
    echo -e "\n${YELLOW}[PHASE 2] Advanced Content Discovery${NC}"
    
    # Historical URLs
    echo -e "${BLUE}[+] Gathering historical URLs...${NC}"
    echo $TARGET | waybackurls > $WORKSPACE/urls/wayback.txt
    echo $TARGET | gau --threads $THREADS > $WORKSPACE/urls/gau.txt
    echo $TARGET | katana -u -silent -f qurl > $WORKSPACE/urls/katana.txt
    
    # Subdomain URLs
    echo -e "${BLUE}[+] Gathering subdomain URLs...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | waybackurls > $WORKSPACE/urls/wayback_subs.txt
    cat $WORKSPACE/subdomains/all_subs.txt | gau --threads $THREADS > $WORKSPACE/urls/gau_subs.txt
    cat $WORKSPACE/subdomains/all_subs.txt | katana -u -silent -f qurl > $WORKSPACE/urls/katana_subs.txt
    
    # Combine all URLs
    cat $WORKSPACE/urls/*.txt | sort -u > $WORKSPACE/urls/all_urls.txt
    
    # Extract parameters
    echo -e "${BLUE}[+] Extracting parameters...${NC}"
    cat $WORKSPACE/urls/all_urls.txt | grep -oE '(\?|&)([^=]+)=([^&]*)' | sort -u > $WORKSPACE/params/all_params.txt
    cat $WORKSPACE/urls/all_urls.txt | urldedupe -s > $WORKSPACE/urls/unique_urls.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/urls/all_urls.txt | wc -l) URLs and $(cat $WORKSPACE/params/all_params.txt | wc -l) unique parameters${NC}"
}

# Phase 3: Live Host Discovery & Tech Stack Analysis
live_host_discovery() {
    echo -e "\n${YELLOW}[PHASE 3] Live Host Discovery & Tech Stack Analysis${NC}"
    
    # Find live hosts with detailed info
    echo -e "${BLUE}[+] Probing live hosts...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | httpx -silent -tech-detect -status-code -title -follow-redirects -server -cdn -ip -cname -location -method -timeout $TIMEOUT -threads $THREADS -o $WORKSPACE/live_hosts_detailed.txt
    
    # Extract live URLs
    cat $WORKSPACE/live_hosts_detailed.txt | awk '{print $1}' > $WORKSPACE/live_hosts.txt
    
    # Technology categorization
    echo -e "${BLUE}[+] Categorizing technologies...${NC}"
    grep -i "wordpress" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/wordpress.txt
    grep -i "laravel" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/laravel.txt
    grep -i "node.js" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/nodejs.txt
    grep -i "django" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/django.txt
    grep -i "java" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/java.txt
    grep -i "asp.net" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/aspnet.txt
    grep -i "react" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/react.txt
    grep -i "vue" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/vue.txt
    
    # Port scanning on important hosts
    echo -e "${BLUE}[+] Port scanning important hosts...${NC}"
    cat $WORKSPACE/live_hosts.txt | head -20 | sed 's|https\?://||' | cut -d'/' -f1 | naabu -top-ports 1000 -silent -o $WORKSPACE/ports/naabu_scan.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/live_hosts.txt | wc -l) live hosts${NC}"
}

# Phase 4: Deep JavaScript Analysis
javascript_analysis() {
    echo -e "\n${YELLOW}[PHASE 4] Deep JavaScript Analysis${NC}"
    
    # Find JS files
    echo -e "${BLUE}[+] Discovering JavaScript files...${NC}"
    cat $WORKSPACE/live_hosts.txt | subjs -c $THREADS > $WORKSPACE/js/all_js_files.txt
    
    # Advanced JS analysis
    echo -e "${BLUE}[+] Performing deep JS analysis...${NC}"
    
    while read js_file; do
        if [[ ! -z "$js_file" ]]; then
            filename=$(echo $js_file | sed 's|https\?://||' | tr '/:' '_')
            echo "Analyzing: $js_file"
            
            # Download JS file
            curl -s -A "$USER_AGENT" "$js_file" > "$WORKSPACE/js/raw_$filename.js" 2>/dev/null
            
            # Extract endpoints - FIXED QUOTE ESCAPING
            curl -s -A "$USER_AGENT" "$js_file" | grep -oE '("|'"'"')((/api|/v[0-9]|/graphql|/rest)[^"'"'"']+)("|'"'"')' | sed 's/["'"'"']//g' >> $WORKSPACE/js/endpoints_from_js.txt
            curl -s -A "$USER_AGENT" "$js_file" | grep -oE 'fetch\(['"'"'\"]([^'"'"'\"]+)['"'"'\"]' | sed "s/fetch(['\"']//" | sed "s/['\"']//" >> $WORKSPACE/js/fetch_endpoints.txt
            curl -s -A "$USER_AGENT" "$js_file" | grep -oE 'axios\.(get|post|put|delete)\(['"'"'\"]([^'"'"'\"]+)['"'"'\"]' >> $WORKSPACE/js/axios_endpoints.txt
            curl -s -A "$USER_AGENT" "$js_file" | grep -oE '\.ajax\([^)]+' | grep -oE 'url:['"'"'\"]([^'"'"'\"]+)['"'"'\"]' | sed "s/url:['\"']//" | sed "s/['\"']//" >> $WORKSPACE/js/ajax_endpoints.txt
            
            # Find secrets and keys
            curl -s -A "$USER_AGENT" "$js_file" | grep -E -o "(api[_-]?key|secret|token|password|auth|jwt)[^a-zA-Z0-9][=:]['\" ]?[a-zA-Z0-9]{16,64}" >> $WORKSPACE/secrets/potential_secrets.txt
            curl -s -A "$USER_AGENT" "$js_file" | grep -E -o "([0-9a-zA-Z+/]{40,})" >> $WORKSPACE/secrets/base64_strings.txt
            
            # DOM XSS sinks
            curl -s -A "$USER_AGENT" "$js_file" | grep -E "(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|location\.|window\.open)" >> $WORKSPACE/js/dom_xss_sinks.txt
            
            # Third-party dependencies
            curl -s -A "$USER_AGENT" "$js_file" | grep -E "(require\(|import |from |jquery|react|vue|angular)" >> $WORKSPACE/dependencies/js_dependencies.txt
        fi
    done < $WORKSPACE/js/all_js_files.txt
    
    # Process findings
    cat $WORKSPACE/js/endpoints_from_js.txt $WORKSPACE/js/fetch_endpoints.txt $WORKSPACE/js/axios_endpoints.txt $WORKSPACE/js/ajax_endpoints.txt | sort -u > $WORKSPACE/js/all_endpoints_from_js.txt
    
    # Use secretfinder for advanced secret detection
    echo -e "${BLUE}[+] Running advanced secret detection...${NC}"
    if [[ -f "$TOOLS_DIR/SecretFinder/SecretFinder.py" ]]; then
        while read js_file; do
            python3 $TOOLS_DIR/SecretFinder/SecretFinder.py -i $js_file -o cli >> $WORKSPACE/secrets/secretfinder_results.txt 2>/dev/null
        done < $WORKSPACE/js/all_js_files.txt
    fi
    
    echo -e "${GREEN}[+] JS Analysis complete:${NC}"
    echo -e "  - $(cat $WORKSPACE/js/all_js_files.txt | wc -l) JS files"
    echo -e "  - $(cat $WORKSPACE/js/all_endpoints_from_js.txt | wc -l) endpoints from JS"
    echo -e "  - $(cat $WORKSPACE/secrets/potential_secrets.txt | wc -l) potential secrets"
}

# Phase 5: API & Business Logic Intelligence
api_business_logic() {
    echo -e "\n${YELLOW}[PHASE 5] API & Business Logic Intelligence${NC}"
    
    # Extract API endpoints from all sources
    echo -e "${BLUE}[+] Mapping API endpoints...${NC}"
    cat $WORKSPACE/urls/all_urls.txt | grep -E "/api/|/v[0-9]/|/graphql|/rest|/jsonrpc" > $WORKSPACE/api/all_api_endpoints.txt
    cat $WORKSPACE/js/all_endpoints_from_js.txt >> $WORKSPACE/api/all_api_endpoints.txt
    
    # Categorize APIs
    grep -E "/api/(user|account|profile|member|customer)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/user_management.txt
    grep -E "/api/(order|cart|checkout|payment|product|invoice)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/ecommerce.txt
    grep -E "/api/(admin|manage|settings|config|dashboard)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/admin_endpoints.txt
    grep -E "graphql" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/graphql_endpoints.txt
    grep -E "/api/(file|upload|document|image)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/file_operations.txt
    
    # Detect API sequences and workflows
    detect_api_workflows
    
    # Test GraphQL endpoints
    test_graphql_endpoints
    
    # Find API documentation
    find_api_documentation
    
    # API parameter analysis
    analyze_api_parameters
}

detect_api_workflows() {
    echo -e "${BLUE}[+] Detecting API workflows...${NC}"
    
    # E-commerce workflow
    cat $WORKSPACE/api/ecommerce.txt | grep -E "(add|create|new)" > $WORKSPACE/workflows/cart_add.txt
    cat $WORKSPACE/api/ecommerce.txt | grep -E "(checkout|payment|purchase)" > $WORKSPACE/workflows/checkout.txt
    cat $WORKSPACE/api/ecommerce.txt | grep -E "(confirm|complete|success)" > $WORKSPACE/workflows/payment_confirm.txt
    
    # User management workflow
    cat $WORKSPACE/api/user_management.txt | grep -E "(register|signup|create)" > $WORKSPACE/workflows/registration.txt
    cat $WORKSPACE/api/user_management.txt | grep -E "(login|signin|auth)" > $WORKSPACE/workflows/login.txt
    cat $WORKSPACE/api/user_management.txt | grep -E "(password|reset|forgot)" > $WORKSPACE/workflows/password_reset.txt
    cat $WORKSPACE/api/user_management.txt | grep -E "(profile|update|edit)" > $WORKSPACE/workflows/profile_update.txt
    
    echo -e "${GREEN}[+] Detected $(ls $WORKSPACE/workflows/*.txt | wc -l) potential workflows${NC}"
}

test_graphql_endpoints() {
    echo -e "${BLUE}[+] Testing GraphQL endpoints...${NC}"
    
    while read endpoint; do
        # Test GraphQL introspection
        response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" \
            -d '{"query":"{ __schema { types { name } } }"}' \
            "$endpoint" 2>/dev/null)
        
        if echo "$response" | grep -q "__schema"; then
            echo "$endpoint - Introspection enabled" >> $WORKSPACE/api/graphql_introspection.txt
            # Save schema for analysis
            curl -s -X POST -H "Content-Type: application/json" \
                -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }"}' \
                "$endpoint" > "$WORKSPACE/api/graphql_schema_$(echo $endpoint | sed 's|https\?://||' | tr '/:' '_').json" 2>/dev/null
        fi
        
        # Test for GraphQL without introspection
        response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" \
            -d '{"query":"{ __typename }"}' \
            "$endpoint" 2>/dev/null)
            
        if echo "$response" | grep -q "__typename"; then
            echo "$endpoint" >> $WORKSPACE/api/working_graphql.txt
        fi
    done < $WORKSPACE/api/graphql_endpoints.txt
}

find_api_documentation() {
    echo -e "${BLUE}[+] Looking for API documentation...${NC}"
    
    common_docs=("/api/docs" "/swagger" "/swagger-ui" "/api/swagger" "/v1/docs" "/v2/docs" "/redoc" "/api/redoc" "/graphql" "/graphiql" "/playground" "/api/playground")
    
    for host in $(cat $WORKSPACE/live_hosts.txt); do
        for doc_path in "${common_docs[@]}"; do
            url="$host$doc_path"
            status=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: $USER_AGENT" "$url")
            if [[ $status == "200" ]]; then
                echo "$url" >> $WORKSPACE/api/documentation.txt
            fi
        done
    done
}

analyze_api_parameters() {
    echo -e "${BLUE}[+] Analyzing API parameters...${NC}"
    
    # Extract parameters from API endpoints
    cat $WORKSPACE/api/all_api_endpoints.txt | grep -oE '(\?|&)([^=]+)=([^&]*)' | sort -u > $WORKSPACE/api/api_params.txt
    
    # Find potential IDOR parameters
    cat $WORKSPACE/api/all_api_endpoints.txt | grep -oE '(\?|&)(user|account|id|order|invoice|profile)[_ ]?id=([^&]*)' > $WORKSPACE/api/idor_params.txt
    
    # Find mass assignment parameters
    cat $WORKSPACE/api/all_api_endpoints.txt | grep -oE '(\?|&)(role|admin|privilege|permission|type)=([^&]*)' > $WORKSPACE/api/mass_assignment_params.txt
}

# Phase 6: Cloud & Infrastructure Reconnaissance
cloud_analysis() {
    echo -e "\n${YELLOW}[PHASE 6] Cloud & Infrastructure Reconnaissance${NC}"
    
    # Cloud IP detection
    echo -e "${BLUE}[+] Analyzing cloud infrastructure...${NC}"
    cat $WORKSPACE/subdomains/resolved_ips.txt | grep -E "(aws|amazon|google|azure|cloudfront|akamai|fastly)" > $WORKSPACE/cloud/cloud_ips.txt
    
    # Cloud bucket discovery
    check_cloud_buckets
    
    # Cloud metadata testing
    check_cloud_metadata
    
    # CORS misconfiguration testing
    test_cors_misconfig
    
    # DNS analysis
    analyze_dns
}

check_cloud_buckets() {
    echo -e "${BLUE}[+] Checking cloud storage...${NC}"
    
    # S3 buckets
    common_buckets=("assets" "media" "storage" "backup" "archive" "logs" "www" "web" "app" "dev" "test" "prod")
    
    for bucket in "${common_buckets[@]}"; do
        for domain in "$TARGET" "$(echo $TARGET | cut -d'.' -f1)"; do
            # AWS S3
            aws s3 ls "s3://$domain-$bucket" 2>/dev/null && echo "S3 bucket: $domain-$bucket" >> $WORKSPACE/cloud/s3_buckets.txt
            aws s3 ls "s3://$bucket-$domain" 2>/dev/null && echo "S3 bucket: $bucket-$domain" >> $WORKSPACE/cloud/s3_buckets.txt
            aws s3 ls "s3://$domain.$bucket" 2>/dev/null && echo "S3 bucket: $domain.$bucket" >> $WORKSPACE/cloud/s3_buckets.txt
            
            # DigitalOcean Spaces
            curl -s "https://$domain-$bucket.nyc3.digitaloceanspaces.com" | grep -q "NoSuchBucket" || echo "DO Space: $domain-$bucket.nyc3.digitaloceanspaces.com" >> $WORKSPACE/cloud/do_spaces.txt
        done
    done
}

check_cloud_metadata() {
    echo -e "${BLUE}[+] Testing cloud metadata...${NC}"
    
    metadata_endpoints=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/user-data/"
        "http://169.254.169.254/latest/dynamic/instance-identity/document"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    )
    
    for host in $(cat $WORKSPACE/live_hosts.txt | head -10); do
        for endpoint in "${metadata_endpoints[@]}"; do
            full_url="$host$(echo $endpoint | sed 's|http://[^/]*||')"
            status=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: $USER_AGENT" "$full_url")
            if [[ $status != "404" && $status != "000" ]]; then
                echo "$full_url" >> $WORKSPACE/cloud/metadata_endpoints.txt
            fi
        done
    done
}

test_cors_misconfig() {
    echo -e "${BLUE}[+] Testing CORS misconfigurations...${NC}"
    
    for host in $(cat $WORKSPACE/live_hosts.txt | head -20); do
        # Test with origin header
        response=$(curl -s -I -H "Origin: https://evil.com" -H "User-Agent: $USER_AGENT" "$host")
        if echo "$response" | grep -i "access-control-allow-origin" | grep -q "evil.com"; then
            echo "$host - CORS misconfiguration: Reflects evil.com" >> $WORKSPACE/cors/misconfigurations.txt
        elif echo "$response" | grep -i "access-control-allow-origin" | grep -q "*"; then
            echo "$host - CORS misconfiguration: Allows *" >> $WORKSPACE/cors/misconfigurations.txt
        fi
    done
}

analyze_dns() {
    echo -e "${BLUE}[+] Analyzing DNS records...${NC}"
    
    # Get comprehensive DNS records
    dig $TARGET ANY > $WORKSPACE/dns/full_dns.txt
    dig $TARGET MX >> $WORKSPACE/dns/full_dns.txt
    dig $TARGET TXT >> $WORKSPACE/dns/full_dns.txt
    dig $TARGET NS >> $WORKSPACE/dns/full_dns.txt
    
    # SPF and DMARC records
    dig $TARGET TXT | grep -E "(spf|dmarc)" > $WORKSPACE/dns/email_security.txt
}

# Phase 7: Advanced Vulnerability Scanning
vulnerability_scanning() {
    echo -e "\n${YELLOW}[PHASE 7] Advanced Vulnerability Scanning${NC}"
    
    # Run nuclei with all templates
    echo -e "${BLUE}[+] Running Nuclei comprehensive scan...${NC}"
    cat $WORKSPACE/live_hosts.txt | nuclei -t ~/nuclei-templates/ -severity low,medium,high,critical -etags intrusive -o $WORKSPACE/results/nuclei_results.txt -timeout $TIMEOUT -rate-limit $THREADS
    
    # Technology-specific scanning
    echo -e "${BLUE}[+] Running technology-specific scans...${NC}"
    if [[ -s $WORKSPACE/tech/wordpress.txt ]]; then
        cat $WORKSPACE/tech/wordpress.txt | awk '{print $1}' | nuclei -t ~/nuclei-templates/technologies/wordpress/ -o $WORKSPACE/results/nuclei_wordpress.txt
    fi
    
    if [[ -s $WORKSPACE/tech/laravel.txt ]]; then
        cat $WORKSPACE/tech/laravel.txt | awk '{print $1}' | nuclei -t ~/nuclei-templates/technologies/laravel/ -o $WORKSPACE/results/nuclei_laravel.txt
    fi
    
    # Custom vulnerability checks
    custom_vulnerability_checks
    
    # API-specific testing
    api_vulnerability_checks
}

custom_vulnerability_checks() {
    echo -e "${BLUE}[+] Running custom vulnerability checks...${NC}"
    
    # IDOR pattern detection
    cat $WORKSPACE/urls/all_urls.txt | grep -E "\?(user|account|id|order|invoice|profile)[_ ]?id=" > $WORKSPACE/results/potential_idor.txt
    
    # Open redirect detection
    cat $WORKSPACE/urls/all_urls.txt | grep -E "\?(redirect|return|next|url|goto|target)=" > $WORKSPACE/results/potential_redirects.txt
    
    # SSRF parameter detection
    cat $WORKSPACE/urls/all_urls.txt | grep -E "\?(url|proxy|api|endpoint|request|path)=" > $WORKSPACE/results/potential_ssrf.txt
    
    # SQL injection pattern detection
    cat $WORKSPACE/urls/all_urls.txt | grep -E "\?(id|user|account|order|query|search)=" > $WORKSPACE/results/potential_sqli.txt
    
    # File inclusion parameters
    cat $WORKSPACE/urls/all_urls.txt | grep -E "\?(file|path|include|page|template)=" > $WORKSPACE/results/potential_lfi.txt
}

api_vulnerability_checks() {
    echo -e "${BLUE}[+] Running API vulnerability checks...${NC}"
    
    # Test for broken object level authorization
    while read api_endpoint; do
        # Replace ID patterns with other user's IDs (conceptual)
        echo "$api_endpoint" | sed 's/\/[0-9]\+/\//' >> $WORKSPACE/api/bola_patterns.txt
    done < $WORKSPACE/api/user_management.txt
    
    # Test for excessive data exposure
    cat $WORKSPACE/api/all_api_endpoints.txt | grep -E "/(users|accounts|profiles)$" > $WORKSPACE/api/excessive_data_endpoints.txt
    
    # Test for mass assignment
    cat $WORKSPACE/api/all_api_endpoints.txt | grep -E "(create|update|edit)" > $WORKSPACE/api/mass_assignment_endpoints.txt
}

# Phase 8: Authentication & Authorization Testing
auth_testing() {
    echo -e "\n${YELLOW}[PHASE 8] Authentication & Authorization Testing${NC}"
    
    # Find authentication endpoints
    echo -e "${BLUE}[+] Identifying authentication endpoints...${NC}"
    cat $WORKSPACE/urls/all_urls.txt | grep -E "(login|signin|auth|authenticate|logout|signout|register|signup)" > $WORKSPACE/auth/auth_endpoints.txt
    
    # Find password reset endpoints
    cat $WORKSPACE/urls/all_urls.txt | grep -E "(password|reset|forgot|recover)" > $WORKSPACE/auth/password_reset_endpoints.txt
    
    # Find admin panels
    cat $WORKSPACE/urls/all_urls.txt | grep -E "(admin|manage|dashboard|control|panel)" > $WORKSPACE/auth/admin_panels.txt
    
    # Test for default credentials (conceptual - would need wordlists)
    echo -e "${BLUE}[+] Testing for common vulnerabilities...${NC}"
    
    # JWT testing endpoints
    cat $WORKSPACE/urls/all_urls.txt | grep -E "(token|jwt|auth)" > $WORKSPACE/auth/jwt_endpoints.txt
}

# Phase 9: Intelligence Gathering & Reporting
generate_intelligence_report() {
    echo -e "\n${YELLOW}[PHASE 9] Generating Intelligence Report${NC}"
    
    REPORT_FILE="$WORKSPACE/reconpro_intelligence_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                   RECONPRO INTELLIGENCE REPORT               ║"
        echo "║                    Advanced Reconnaissance                   ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "TARGET: $TARGET"
        echo "GENERATED: $(date)"
        echo "DURATION: $(($SECONDS / 60)) minutes"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo " EXECUTIVE SUMMARY"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "📊 DISCOVERY METRICS:"
        echo "─────────────────────"
        echo "• Subdomains Discovered: $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l)"
        echo "• Live Hosts: $(cat $WORKSPACE/live_hosts.txt | wc -l)"
        echo "• URLs Found: $(cat $WORKSPACE/urls/all_urls.txt | wc -l)"
        echo "• JavaScript Files: $(cat $WORKSPACE/js/all_js_files.txt | wc -l)"
        echo "• API Endpoints: $(cat $WORKSPACE/api/all_api_endpoints.txt | wc -l)"
        echo "• Unique Parameters: $(cat $WORKSPACE/params/all_params.txt | wc -l)"
        echo ""
        echo "⚠️  CRITICAL FINDINGS:"
        echo "─────────────────────"
        echo "• Nuclei High/Critical: $(grep -E "(HIGH|CRITICAL)" $WORKSPACE/results/nuclei_results.txt 2>/dev/null | wc -l)"
        echo "• GraphQL Introspection: $(cat $WORKSPACE/api/graphql_introspection.txt 2>/dev/null | wc -l)"
        echo "• Potential Secrets: $(cat $WORKSPACE/secrets/potential_secrets.txt 2>/dev/null | wc -l)"
        echo "• CORS Misconfigurations: $(cat $WORKSPACE/cors/misconfigurations.txt 2>/dev/null | wc -l)"
        echo "• Cloud Buckets: $(cat $WORKSPACE/cloud/s3_buckets.txt $WORKSPACE/cloud/do_spaces.txt 2>/dev/null | wc -l)"
        echo ""
        echo "🎯 BUSINESS LOGIC TARGETS:"
        echo "──────────────────────────"
        echo "• User Management Endpoints: $(cat $WORKSPACE/api/user_management.txt 2>/dev/null | wc -l)"
        echo "• E-commerce Endpoints: $(cat $WORKSPACE/api/ecommerce.txt 2>/dev/null | wc -l)"
        echo "• Admin Endpoints: $(cat $WORKSPACE/api/admin_endpoints.txt 2>/dev/null | wc -l)"
        echo "• Authentication Endpoints: $(cat $WORKSPACE/auth/auth_endpoints.txt 2>/dev/null | wc -l)"
        echo "• API Workflows: $(ls $WORKSPACE/workflows/*.txt 2>/dev/null | wc -l)"
        echo ""
        echo "🔧 TECHNOLOGY STACK:"
        echo "────────────────────"
        echo "• WordPress: $(cat $WORKSPACE/tech/wordpress.txt 2>/dev/null | wc -l) instances"
        echo "• Laravel: $(cat $WORKSPACE/tech/laravel.txt 2>/dev/null | wc -l) instances"
        echo "• Node.js: $(cat $WORKSPACE/tech/nodejs.txt 2>/dev/null | wc -l) instances"
        echo "• React: $(cat $WORKSPACE/tech/react.txt 2>/dev/null | wc -l) instances"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo " RECOMMENDED NEXT STEPS"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "🚀 IMMEDIATE ACTIONS (High Value):"
        echo "──────────────────────────────────"
        echo "1. Manual API Testing - Focus on business logic workflows"
        echo "2. GraphQL Endpoints - Test for introspection and query abuse"
        echo "3. IDOR Testing - Check user_management.txt endpoints"
        echo "4. Secret Validation - Investigate potential_secrets.txt"
        echo "5. CORS Exploitation - Test misconfigurations manually"
        echo ""
        echo "🎯 BUSINESS LOGIC TESTING:"
        echo "──────────────────────────"
        echo "• E-commerce Flow: Test cart → checkout → payment sequence"
        echo "• User Registration: Test registration → verification → login"
        echo "• Password Reset: Test token security and predictability"
        echo "• Admin Functions: Test privilege escalation paths"
        echo ""
        echo "🔍 DEEP MANUAL TESTING:"
        echo "───────────────────────"
        echo "• JavaScript Analysis: Review extracted endpoints and secrets"
        echo "• API Parameter Testing: Test all parameters for injection"
        echo "• Authentication Bypass: Test auth endpoints for weaknesses"
        echo "• File Upload Testing: Test file_operations.txt endpoints"
        echo ""
        echo "📊 MONITORING:"
        echo "──────────────"
        echo "• Schedule weekly rescans with: ./reconpro.sh $TARGET"
        echo "• Monitor for new subdomains and endpoints"
        echo "• Track technology changes and new deployments"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo " KEY FILES FOR REVIEW"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "• $WORKSPACE/live_hosts.txt - All active targets"
        echo "• $WORKSPACE/api/ - API endpoints categorized by function"
        echo "• $WORKSPACE/workflows/ - Business logic sequences"
        echo "• $WORKSPACE/results/ - Vulnerability scan results"
        echo "• $WORKSPACE/secrets/ - Potential secrets and keys"
        echo "• $WORKSPACE/js/ - JavaScript analysis results"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo " END OF REPORT"
        echo "════════════════════════════════════════════════════════════════"
        
    } > $REPORT_FILE
    
    # Create quick access summary
    echo -e "${GREEN}[+] Full report: $REPORT_FILE${NC}"
    
    # Show critical findings immediately
    echo -e "\n${RED}🚨 CRITICAL FINDINGS SUMMARY:${NC}"
    grep -E "(HIGH|CRITICAL)" $WORKSPACE/results/nuclei_results.txt 2>/dev/null | head -10
    if [[ -s $WORKSPACE/api/graphql_introspection.txt ]]; then
        echo -e "${RED}❌ GraphQL Introspection Enabled:${NC}"
        cat $WORKSPACE/api/graphql_introspection.txt
    fi
}

# Main execution
main() {
    START_TIME=$SECONDS
    
    if [[ -z "$TARGET" ]]; then
        echo "Usage: $0 <domain>"
        echo "Example: $0 example.com"
        exit 1
    fi
    
    echo -e "${PURPLE}[+] Starting ReconPro for: $TARGET${NC}"
    echo -e "${PURPLE}[+] Start time: $(date)${NC}"
    
    check_dependencies
    
    # Execute all phases
    subdomain_discovery
    content_discovery
    live_host_discovery
    javascript_analysis
    api_business_logic
    cloud_analysis
    vulnerability_scanning
    auth_testing
    generate_intelligence_report
    
    END_TIME=$SECONDS
    DURATION=$((END_TIME - START_TIME))
    
    echo -e "\n${GREEN}✅ ReconPro completed in $(($DURATION / 60)) minutes!${NC}"
    echo -e "${YELLOW}📁 Results saved to: $WORKSPACE${NC}"
    echo -e "${CYAN}🎯 Focus on manual testing for business logic vulnerabilities!${NC}"
    
    # Show quick stats
    echo -e "\n${GREEN}📊 QUICK STATS:${NC}"
    echo -e "Subdomains: $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l)"
    echo -e "Live Hosts: $(cat $WORKSPACE/live_hosts.txt | wc -l)"
    echo -e "API Endpoints: $(cat $WORKSPACE/api/all_api_endpoints.txt | wc -l)"
    echo -e "Critical Vulns: $(grep -c "HIGH\|CRITICAL" $WORKSPACE/results/nuclei_results.txt 2>/dev/null)"
}

# Signal handling
trap 'echo -e "${RED}\n[!] Script interrupted. Partial results saved to $WORKSPACE${NC}"; exit 1' INT

# Run main function
main "$@"
