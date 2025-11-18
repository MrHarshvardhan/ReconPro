#!/bin/bash

echo "Installing ReconPro v3.0 and all dependencies..."

# Create directories
mkdir -p tools wordlists scans

# Install Go tools
echo "Installing Go tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/lc/subjs@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/ffuf/ffuf@latest

# Install Python tools
echo "Installing Python tools..."
pip3 install requests beautifulsoup4 lxml

# Clone repositories
echo "Cloning additional tools..."
git clone https://github.com/m4ll0k/SecretFinder.git tools/SecretFinder
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Download wordlists
echo "Downloading wordlists..."
wget -q -O wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
wget -q -O wordlists/resolvers.txt https://raw.githubusercontent.com/projectdiscovery/dnsx/main/wordlists/dns-resolvers.txt

# Update nuclei templates
echo "Updating Nuclei templates..."
nuclei -update-templates

# Make script executable
chmod +x reconpro.sh

echo -e "\n✅ Installation complete!"
echo -e "Usage: ./reconpro.sh example.com"
