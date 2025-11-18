
## ReconPro is a powerful automated reconnaissance tool designed for security researchers and penetration testers.

# 1. Install
chmod +x install.sh
./install.sh

# 2. Run
./reconpro.sh example.com

# 3. Monitor progress and check results
ls -la scans/example.com/


# What Makes This Better Than ReconFTW

1. Deep JavaScript Analysis - Extracts endpoints, secrets, DOM XSS sinks
2. Business Logic Mapping - Identifies workflows and sequences
3. API Intelligence - Categorizes endpoints by business function
4. Cloud Infrastructure - Comprehensive cloud testing
5. Authentication Testing - Specialized auth endpoint analysis
6. Advanced Secret Detection - Multiple secret finding methods
7. CORS Testing - Automated CORS misconfiguration detection
8. GraphQL Intelligence - Schema extraction and analysis
9. Technology Fingerprinting - Detailed tech stack analysis
10. Actionable Reporting - Prioritized next steps for manual testing

# Result

scans/abc.com/

├── live_hosts.txt          # 45 live websites

├── api/ecommerce.txt       # 12 payment endpoints  

├── js/all_endpoints.txt    # 89 hidden APIs from JS

├── results/nuclei_results.txt  # 3 critical vulnerabilities

└── reconpro_report.txt     # Executive summary
