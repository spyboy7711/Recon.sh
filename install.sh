#!/bin/bash



mkdir /root/tools

cd /root/tools && git clone https://github.com/spyboy7711/word-lists.git
echo "[1] Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >> /dev/null 2>&1 && ln -s ~/go/bin/subfinder /usr/local/bin/;

echo "[2] Installing Subfinder..."
go install -v github.com/tomnomnom/assetfinder@latest >> /dev/null 2>&1 && ln -s ~/go/bin/assetfinder /usr/local/bin/;

echo "[3] Installing Subfinder..."
cd /tmp && wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux > /dev/null 2>&1 && chmod +x findomain-linux && mv ./findomain-linux /usr/local/bin/findomain;

echo "[4] Installing Ctfr..."
cd /root/tools && git clone https://github.com/UnaPibaGeek/ctfr.git && cd ctfr && pip3 install -r requirements.txt

echo "[5] Installing gauplus..."
go install github.com/lc/gau/v2/cmd/gau@latest > /dev/null 2>&1 && ln -s ~/go/bin/gau /usr/local/bin/;

echo "[6] Installing waybackurls..."
go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1 && ln -s ~/go/bin/waybackurls /usr/local/bin/;

echo "[7] Installing Github-subdomains..."
go get -u github.com/gwen001/github-subdomains > /dev/null 2>&1 && ln -s ~/go/bin/github-subdomains /usr/local/bin/;

echo "[8] Installing crobat..."
go install github.com/cgboal/sonarsearch/cmd/crobat@latest > /dev/null 2>&1 && ln -s ~/go/bin/crobat /usr/local/bin/;

echo "[9] Installing puredns..."
go install github.com/d3mondev/puredns/v2@latest > /dev/null 2>&1 && ln -s ~/go/bin/puredns /usr/local/bin;

echo "[10] Installing AnalyticsRelationships..."
cd /root/tools && git clone https://github.com/Josue87/AnalyticsRelationships.git && cd AnalyticsRelationships/Python && sudo pip3 install -r requirements.txt

echo "[11] Installing DNSCewl..."
cd /root/tools && git clone https://github.com/codingo/DNSCewl.git && cp /root/tools/DNSCewl/DNScewl /usr/local/bin/;

echo "[12] Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest > /dev/null 2>&1 && ln -s ~/go/bin/httpx /usr/local/bin/;

echo "[13] Installing subjack..."
go install github.com/haccer/subjack@latest > /dev/null 2>&1 && ln -s ~/go/bin/subjack /usr/local/bin/;

echo "[14] Installing nuclei..."
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest > /dev/null 2>&1 && ln -s ~/go/bin/nuclei /usr/local/bin/;
nuclei -update-templates > /dev/null 2>&1;

echo "[15] Installing naabu..."
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1 && ln -s ~/go/bin/naabu /usr/local/bin/;

echo "[16] Installing gf pattern..."
go install github.com/tomnomnom/gf@latest > /dev/null 2>&1 && ln -s ~/go/bin/gf /usr/local/bin/;
mkdir ~/.gf
cd /root/tools && git clone https://github.com/tomnomnom/gf.git && git clone https://github.com/1ndianl33t/Gf-Patterns && cp -r /root/tools/gf/examples ~/.gf && cp -r /root/tools/Gf-Patterns/*.json ~/.gf

echo "[17] Installing kxss..."
go get -u github.com/tomnomnom/hacks/kxss > /dev/null 2>&1 && ln -s ~/go/bin/kxss /usr/local/bin/;

echo "[18] Installing dalfox..."
go install github.com/hahwul/dalfox/v2@latest > /dev/null 2>&1 && ln -s ~/go/bin/dalfox /usr/local/bin/;

echo "[19] Installing LinkFinder..."
cd /root/tools && git clone https://github.com/GerbenJavado/LinkFinder.git && cd LinkFinder && pip3 install -r requirements.txt > /dev/null 2>&1 && python3 setup.py install > /dev/null 2>&1;

echo "[20] Installing SecretFinder..."
cd /root/tools && git clone https://github.com/m4ll0k/SecretFinder.git > /dev/null 2>&1 && cd SecretFinder && pip3 install -r requirements.txt > /dev/null 2>&1;

echo "[20] Installing qsreplace..."
go install github.com/tomnomnom/qsreplace@latest > /dev/null 2>&1 && ln -s ~/go/bin/qsreplace /usr/local/bin/;

echo "[20] Installing anew..."
go install github.com/tomnomnom/anew@latest > /dev/null 2>&1 && ln -s ~/go/bin/anew /usr/local/bin/;

















