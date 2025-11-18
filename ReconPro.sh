#!/bin/bash

# ReconPro - Advanced Reconnaissance Framework v3.1

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
echo -e "${GREEN}ReconPro v3.1 - Domain-Focused Reconnaissance${NC}"
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

# Function to filter only target domain and subdomains
filter_target_domains() {
    local input_file=$1
    local output_file=$2
    # Match exact domain and subdomains only
    grep -E "([a-zA-Z0-9_-]+\.)*$TARGET$" "$input_file" > "$output_file"
}

# Phase 1: Targeted Subdomain Discovery
subdomain_discovery() {
    echo -e "\n${YELLOW}[PHASE 1] Targeted Subdomain Discovery${NC}"
    
    # Passive enumeration - only for our target
    echo -e "${BLUE}[+] Running targeted subdomain discovery...${NC}"
    subfinder -d $TARGET -silent -t $THREADS > $WORKSPACE/subdomains/subfinder_raw.txt
    filter_target_domains "$WORKSPACE/subdomains/subfinder_raw.txt" "$WORKSPACE/subdomains/subfinder.txt"
    
    assetfinder -subs-only $TARGET > $WORKSPACE/subdomains/assetfinder_raw.txt
    filter_target_domains "$WORKSPACE/subdomains/assetfinder_raw.txt" "$WORKSPACE/subdomains/assetfinder.txt"
    
    amass enum -passive -d $TARGET -o $WORKSPACE/subdomains/amass_raw.txt
    filter_target_domains "$WORKSPACE/subdomains/amass_raw.txt" "$WORKSPACE/subdomains/amass_passive.txt"
    
    # Certificate transparency - filtered for our domain
    echo -e "${BLUE}[+] Checking certificate transparency...${NC}"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > $WORKSPACE/subdomains/cert_sh_raw.txt
    filter_target_domains "$WORKSPACE/subdomains/cert_sh_raw.txt" "$WORKSPACE/subdomains/cert_sh.txt"
    
    # DNS bruteforce - only for our target
    echo -e "${BLUE}[+] DNS bruteforcing target domain...${NC}"
    if [[ -f "$WORDLISTS_DIR/subdomains.txt" ]]; then
        while read sub; do
            host "$sub.$TARGET" 2>/dev/null | grep "has address" | awk '{print $1}' >> $WORKSPACE/subdomains/dns_brute_raw.txt
        done < $WORDLISTS_DIR/subdomains.txt
        filter_target_domains "$WORKSPACE/subdomains/dns_brute_raw.txt" "$WORKSPACE/subdomains/dns_brute.txt"
    fi
    
    # Combine all subdomains and ensure they're only for our target
    cat $WORKSPACE/subdomains/*.txt | sort -u > $WORKSPACE/subdomains/all_subs_raw.txt
    filter_target_domains "$WORKSPACE/subdomains/all_subs_raw.txt" "$WORKSPACE/subdomains/all_subs.txt"
    
    # Add the main domain if not present
    if ! grep -q "^$TARGET$" "$WORKSPACE/subdomains/all_subs.txt"; then
        echo "$TARGET" >> $WORKSPACE/subdomains/all_subs.txt
        sort -u $WORKSPACE/subdomains/all_subs.txt -o $WORKSPACE/subdomains/all_subs.txt
    fi
    
    # Resolve to IPs - only our target's subdomains
    echo -e "${BLUE}[+] Resolving target subdomains to IPs...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | dnsx -silent -a -resp -o $WORKSPACE/subdomains/resolved_ips.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l) subdomains for $TARGET${NC}"
}

# Phase 2: Targeted Content Discovery
content_discovery() {
    echo -e "\n${YELLOW}[PHASE 2] Targeted Content Discovery${NC}"
    
    # Historical URLs - only for our target domain
    echo -e "${BLUE}[+] Gathering historical URLs for $TARGET...${NC}"
    echo $TARGET | waybackurls > $WORKSPACE/urls/wayback_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/urls/wayback_raw.txt > $WORKSPACE/urls/wayback.txt
    
    echo $TARGET | gau --threads $THREADS > $WORKSPACE/urls/gau_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/urls/gau_raw.txt > $WORKSPACE/urls/gau.txt
    
    # Subdomain URLs - only for our verified subdomains
    echo -e "${BLUE}[+] Gathering subdomain URLs...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | waybackurls > $WORKSPACE/urls/wayback_subs_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/urls/wayback_subs_raw.txt > $WORKSPACE/urls/wayback_subs.txt
    
    cat $WORKSPACE/subdomains/all_subs.txt | gau --threads $THREADS > $WORKSPACE/urls/gau_subs_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/urls/gau_subs_raw.txt > $WORKSPACE/urls/gau_subs.txt
    
    # Active crawling - only for our target
    echo -e "${BLUE}[+] Active crawling target domains...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | katana -u -silent -f qurl > $WORKSPACE/urls/katana_subs.txt
    
    # Combine all URLs and ensure they're only for our target
    cat $WORKSPACE/urls/wayback.txt $WORKSPACE/urls/gau.txt $WORKSPACE/urls/wayback_subs.txt $WORKSPACE/urls/gau_subs.txt $WORKSPACE/urls/katana_subs.txt | sort -u > $WORKSPACE/urls/all_urls_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/urls/all_urls_raw.txt > $WORKSPACE/urls/all_urls.txt
    
    # Extract parameters from target URLs only
    echo -e "${BLUE}[+] Extracting parameters from target...${NC}"
    cat $WORKSPACE/urls/all_urls.txt | grep -oE '(\?|&)([^=]+)=([^&]*)' | sort -u > $WORKSPACE/params/all_params.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/urls/all_urls.txt | wc -l) URLs and $(cat $WORKSPACE/params/all_params.txt | wc -l) unique parameters for $TARGET${NC}"
}

# Phase 3: Live Host Discovery & Tech Stack Analysis
live_host_discovery() {
    echo -e "\n${YELLOW}[PHASE 3] Live Host Discovery & Tech Stack Analysis${NC}"
    
    # Find live hosts with detailed info - only our target subdomains
    echo -e "${BLUE}[+] Probing live hosts for $TARGET...${NC}"
    cat $WORKSPACE/subdomains/all_subs.txt | httpx -silent -tech-detect -status-code -title -follow-redirects -server -cdn -ip -cname -location -method -timeout $TIMEOUT -threads $THREADS -o $WORKSPACE/live_hosts_detailed.txt
    
    # Extract live URLs and verify they're for our target
    cat $WORKSPACE/live_hosts_detailed.txt | awk '{print $1}' > $WORKSPACE/live_hosts_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/live_hosts_raw.txt > $WORKSPACE/live_hosts.txt
    
    # Technology categorization for our target only
    echo -e "${BLUE}[+] Categorizing technologies for $TARGET...${NC}"
    grep -i "wordpress" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/wordpress.txt
    grep -i "laravel" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/laravel.txt
    grep -i "node.js" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/nodejs.txt
    grep -i "django" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/django.txt
    grep -i "java" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/java.txt
    grep -i "asp.net" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/aspnet.txt
    grep -i "react" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/react.txt
    grep -i "vue" $WORKSPACE/live_hosts_detailed.txt > $WORKSPACE/tech/vue.txt
    
    # Port scanning on target hosts only
    echo -e "${BLUE}[+] Port scanning target hosts...${NC}"
    cat $WORKSPACE/live_hosts.txt | head -20 | sed 's|https\?://||' | cut -d'/' -f1 | naabu -top-ports 1000 -silent -o $WORKSPACE/ports/naabu_scan.txt
    
    echo -e "${GREEN}[+] Found $(cat $WORKSPACE/live_hosts.txt | wc -l) live hosts for $TARGET${NC}"
}

# Phase 4: Deep JavaScript Analysis
javascript_analysis() {
    echo -e "\n${YELLOW}[PHASE 4] Deep JavaScript Analysis${NC}"
    
    # Find JS files from target domains only
    echo -e "${BLUE}[+] Discovering JavaScript files for $TARGET...${NC}"
    cat $WORKSPACE/live_hosts.txt | subjs -c $THREADS > $WORKSPACE/js/all_js_files_raw.txt
    grep -E "https?://([a-zA-Z0-9_-]+\.)*$TARGET/" $WORKSPACE/js/all_js_files_raw.txt > $WORKSPACE/js/all_js_files.txt
    
    # Advanced JS analysis for target only
    echo -e "${BLUE}[+] Performing deep JS analysis for $TARGET...${NC}"
    
    while read js_file; do
        if [[ ! -z "$js_file" ]]; then
            filename=$(echo $js_file | sed 's|https\?://||' | tr '/:' '_')
            echo "Analyzing: $js_file"
            
            # Download JS file
            curl -s -A "$USER_AGENT" "$js_file" > "$WORKSPACE/js/raw_$filename.js" 2>/dev/null
            
            # Use a temporary file for processing to avoid quote issues
            curl -s -A "$USER_AGENT" "$js_file" > "$WORKSPACE/js/temp_js.js"
            
            # Extract endpoints using temporary file
            grep -oE '("/api|/v[0-9]|/graphql|/rest)[^"]*"' "$WORKSPACE/js/temp_js.js" | tr -d '"' >> $WORKSPACE/js/endpoints_from_js.txt
            grep -oE "('/api|/v[0-9]|/graphql|/rest)[^']*'" "$WORKSPACE/js/temp_js.js" | tr -d "'" >> $WORKSPACE/js/endpoints_from_js.txt
            grep -oE 'fetch\([^)]+' "$WORKSPACE/js/temp_js.js" | grep -oE '["'"'"'][^"'"'"']*["'"'"']' | tr -d '"' | tr -d "'" >> $WORKSPACE/js/fetch_endpoints.txt
            
            # Find secrets and keys
            grep -E -o "(api[_-]?key|secret|token|password|auth|jwt)[^a-zA-Z0-9][=:]['\" ]?[a-zA-Z0-9]{16,64}" "$WORKSPACE/js/temp_js.js" >> $WORKSPACE/secrets/potential_secrets.txt
            
            # DOM XSS sinks
            grep -E "(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\(|location\.|window\.open)" "$WORKSPACE/js/temp_js.js" >> $WORKSPACE/js/dom_xss_sinks.txt
            
            # Third-party dependencies
            grep -E "(require\(|import |from |jquery|react|vue|angular)" "$WORKSPACE/js/temp_js.js" >> $WORKSPACE/dependencies/js_dependencies.txt
            
            # Clean up temp file
            rm -f "$WORKSPACE/js/temp_js.js"
        fi
    done < $WORKSPACE/js/all_js_files.txt
    
    # Process findings and ensure they're for our target
    cat $WORKSPACE/js/endpoints_from_js.txt $WORKSPACE/js/fetch_endpoints.txt | sort -u > $WORKSPACE/js/all_endpoints_from_js_raw.txt
    grep -E "^(/|https?://([a-zA-Z0-9_-]+\.)*$TARGET)" $WORKSPACE/js/all_endpoints_from_js_raw.txt > $WORKSPACE/js/all_endpoints_from_js.txt
    
    echo -e "${GREEN}[+] JS Analysis complete for $TARGET:${NC}"
    echo -e "  - $(cat $WORKSPACE/js/all_js_files.txt | wc -l) JS files"
    echo -e "  - $(cat $WORKSPACE/js/all_endpoints_from_js.txt | wc -l) endpoints from JS"
    echo -e "  - $(cat $WORKSPACE/secrets/potential_secrets.txt | wc -l) potential secrets"
}

# Phase 5: API & Business Logic Intelligence
api_business_logic() {
    echo -e "\n${YELLOW}[PHASE 5] API & Business Logic Intelligence${NC}"
    
    # Extract API endpoints from all sources - target only
    echo -e "${BLUE}[+] Mapping API endpoints for $TARGET...${NC}"
    grep -E "/api/|/v[0-9]/|/graphql|/rest|/jsonrpc" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/api/all_api_endpoints.txt
    cat $WORKSPACE/js/all_endpoints_from_js.txt >> $WORKSPACE/api/all_api_endpoints.txt
    
    # Remove duplicates and ensure they're for our target
    sort -u $WORKSPACE/api/all_api_endpoints.txt -o $WORKSPACE/api/all_api_endpoints.txt
    
    # Categorize APIs for our target
    grep -E "/api/(user|account|profile|member|customer)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/user_management.txt
    grep -E "/api/(order|cart|checkout|payment|product|invoice)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/ecommerce.txt
    grep -E "/api/(admin|manage|settings|config|dashboard)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/admin_endpoints.txt
    grep -E "graphql" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/graphql_endpoints.txt
    grep -E "/api/(file|upload|document|image)" $WORKSPACE/api/all_api_endpoints.txt > $WORKSPACE/api/file_operations.txt
    
    # Detect API sequences and workflows for our target
    detect_api_workflows
    
    # Test GraphQL endpoints for our target
    test_graphql_endpoints
    
    echo -e "${GREEN}[+] API Analysis complete for $TARGET${NC}"
}

detect_api_workflows() {
    echo -e "${BLUE}[+] Detecting API workflows for $TARGET...${NC}"
    
    # E-commerce workflow
    grep -E "(add|create|new)" $WORKSPACE/api/ecommerce.txt > $WORKSPACE/workflows/cart_add.txt
    grep -E "(checkout|payment|purchase)" $WORKSPACE/api/ecommerce.txt > $WORKSPACE/workflows/checkout.txt
    grep -E "(confirm|complete|success)" $WORKSPACE/api/ecommerce.txt > $WORKSPACE/workflows/payment_confirm.txt
    
    # User management workflow
    grep -E "(register|signup|create)" $WORKSPACE/api/user_management.txt > $WORKSPACE/workflows/registration.txt
    grep -E "(login|signin|auth)" $WORKSPACE/api/user_management.txt > $WORKSPACE/workflows/login.txt
    grep -E "(password|reset|forgot)" $WORKSPACE/api/user_management.txt > $WORKSPACE/workflows/password_reset.txt
    grep -E "(profile|update|edit)" $WORKSPACE/api/user_management.txt > $WORKSPACE/workflows/profile_update.txt
    
    echo -e "${GREEN}[+] Detected $(ls $WORKSPACE/workflows/*.txt 2>/dev/null | wc -l) potential workflows for $TARGET${NC}"
}

test_graphql_endpoints() {
    echo -e "${BLUE}[+] Testing GraphQL endpoints for $TARGET...${NC}"
    
    while read endpoint; do
        # Test GraphQL introspection
        response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" \
            -d '{"query":"{ __schema { types { name } } }"}' \
            "$endpoint" 2>/dev/null)
        
        if echo "$response" | grep -q "__schema"; then
            echo "$endpoint - Introspection enabled" >> $WORKSPACE/api/graphql_introspection.txt
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

# Phase 6: Vulnerability Scanning
vulnerability_scanning() {
    echo -e "\n${YELLOW}[PHASE 6] Vulnerability Scanning${NC}"
    
    # Run nuclei only on our target hosts
    echo -e "${BLUE}[+] Running Nuclei on $TARGET...${NC}"
    cat $WORKSPACE/live_hosts.txt | nuclei -t ~/nuclei-templates/ -severity low,medium,high,critical -etags intrusive -o $WORKSPACE/results/nuclei_results.txt -timeout $TIMEOUT -rate-limit $THREADS
    
    # Custom vulnerability checks for our target
    custom_vulnerability_checks
    
    echo -e "${GREEN}[+] Vulnerability scanning complete for $TARGET${NC}"
}

custom_vulnerability_checks() {
    echo -e "${BLUE}[+] Running custom vulnerability checks for $TARGET...${NC}"
    
    # IDOR pattern detection
    grep -E "\?(user|account|id|order|invoice|profile)[_ ]?id=" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/results/potential_idor.txt
    
    # Open redirect detection
    grep -E "\?(redirect|return|next|url|goto|target)=" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/results/potential_redirects.txt
    
    # SSRF parameter detection
    grep -E "\?(url|proxy|api|endpoint|request|path)=" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/results/potential_ssrf.txt
    
    # SQL injection pattern detection
    grep -E "\?(id|user|account|order|query|search)=" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/results/potential_sqli.txt
    
    # File inclusion parameters
    grep -E "\?(file|path|include|page|template)=" $WORKSPACE/urls/all_urls.txt > $WORKSPACE/results/potential_lfi.txt
}

# Phase 7: Intelligence Gathering & Reporting
generate_intelligence_report() {
    echo -e "\n${YELLOW}[PHASE 7] Generating Intelligence Report${NC}"
    
    REPORT_FILE="$WORKSPACE/reconpro_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                   RECONPRO INTELLIGENCE REPORT               ║"
        echo "║                    Domain: $TARGET"
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
        echo "📊 DISCOVERY METRICS for $TARGET:"
        echo "─────────────────────────────────"
        echo "• Subdomains Discovered: $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l)"
        echo "• Live Hosts: $(cat $WORKSPACE/live_hosts.txt | wc -l)"
        echo "• URLs Found: $(cat $WORKSPACE/urls/all_urls.txt | wc -l)"
        echo "• JavaScript Files: $(cat $WORKSPACE/js/all_js_files.txt | wc -l)"
        echo "• API Endpoints: $(cat $WORKSPACE/api/all_api_endpoints.txt | wc -l)"
        echo ""
        echo "⚠️  CRITICAL FINDINGS:"
        echo "─────────────────────"
        echo "• Nuclei High/Critical: $(grep -E "(HIGH|CRITICAL)" $WORKSPACE/results/nuclei_results.txt 2>/dev/null | wc -l)"
        echo "• GraphQL Introspection: $(cat $WORKSPACE/api/graphql_introspection.txt 2>/dev/null | wc -l)"
        echo "• Potential Secrets: $(cat $WORKSPACE/secrets/potential_secrets.txt 2>/dev/null | wc -l)"
        echo ""
        echo "🎯 BUSINESS LOGIC TARGETS:"
        echo "──────────────────────────"
        echo "• User Management Endpoints: $(cat $WORKSPACE/api/user_management.txt 2>/dev/null | wc -l)"
        echo "• E-commerce Endpoints: $(cat $WORKSPACE/api/ecommerce.txt 2>/dev/null | wc -l)"
        echo "• Admin Endpoints: $(cat $WORKSPACE/api/admin_endpoints.txt 2>/dev/null | wc -l)"
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
        echo " RECOMMENDED NEXT STEPS for $TARGET"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "🚀 IMMEDIATE ACTIONS:"
        echo "─────────────────────"
        echo "1. Manual API Testing - Focus on business logic workflows"
        echo "2. GraphQL Endpoints - Test for introspection and query abuse"
        echo "3. IDOR Testing - Check user_management.txt endpoints"
        echo "4. Secret Validation - Investigate potential_secrets.txt"
        echo ""
        echo "🔍 FILES FOR REVIEW:"
        echo "────────────────────"
        echo "• $WORKSPACE/live_hosts.txt - All active targets for $TARGET"
        echo "• $WORKSPACE/api/ - API endpoints for $TARGET"
        echo "• $WORKSPACE/workflows/ - Business logic sequences"
        echo "• $WORKSPACE/results/ - Vulnerability scan results"
        echo ""
    } > $REPORT_FILE
    
    echo -e "${GREEN}[+] Full report: $REPORT_FILE${NC}"
    
    # Show critical findings immediately
    echo -e "\n${RED}🚨 CRITICAL FINDINGS for $TARGET:${NC}"
    grep -E "(HIGH|CRITICAL)" $WORKSPACE/results/nuclei_results.txt 2>/dev/null | head -5
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
        echo "Example: $0 subdomain.example.com"
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
    vulnerability_scanning
    generate_intelligence_report
    
    END_TIME=$SECONDS
    DURATION=$((END_TIME - START_TIME))
    
    echo -e "\n${GREEN}✅ ReconPro completed in $(($DURATION / 60)) minutes!${NC}"
    echo -e "${YELLOW}📁 Results saved to: $WORKSPACE${NC}"
    echo -e "${CYAN}🎯 All results are strictly for: $TARGET and its subdomains${NC}"
    
    # Show quick stats
    echo -e "\n${GREEN}📊 QUICK STATS for $TARGET:${NC}"
    echo -e "Subdomains: $(cat $WORKSPACE/subdomains/all_subs.txt | wc -l)"
    echo -e "Live Hosts: $(cat $WORKSPACE/live_hosts.txt | wc -l)"
    echo -e "API Endpoints: $(cat $WORKSPACE/api/all_api_endpoints.txt | wc -l)"
    echo -e "Critical Vulns: $(grep -c "HIGH\|CRITICAL" $WORKSPACE/results/nuclei_results.txt 2>/dev/null)"
}

# Signal handling
trap 'echo -e "${RED}\n[!] Script interrupted. Partial results saved to $WORKSPACE${NC}"; exit 1' INT

# Run main function
main "$@"
