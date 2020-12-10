sudo apt install git;
sudo apt-get install python3-pip;
sudo apt-get install ruby;
sudo apt-get install screen;
go get -u github.com/tomnomnom/assetfinder;
mkdir tools;
cd tools
git clone https://github.com/aboul3la/Sublist3r.git 
cd Sublist3r
pip3 install dnspython
sudo apt install dnsutils
sudo pip3 install -r requirements.txt
cd ../
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/cmd/subfinder;
sudo apt install snapd
sudo snap install amass
GO111MODULE=auto go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
go get github.com/haccer/subjack
go get -u -v github.com/lukasikic/subzy
GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
git clone https://github.com/projectdiscovery/nuclei-templates.git
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness
cd Python
cd setup
chmod +x setup.sh
bash setup.sh
cd
cd tools
go get github.com/tomnomnom/hacks/filter-resolved
go get -u github.com/dwisiswant0/cf-check
GO111MODULE=on go get -u -v github.com/projectdiscovery/naabu/v2/cmd/naabu
go get -u github.com/tomnomnom/httprobe
GO111MODULE=on go get github.com/jaeles-project/jaeles
jaeles config init
git clone https://github.com/ghsec/ghsec-jaeles-signatures.git jaelesexternal
go get github.com/tomnomnom/waybackurls
GO111MODULE=on go get -u -v github.com/lc/gau
go get -u github.com/tomnomnom/gf
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns.git
mv Gf-Patterns/*.json ~/.gf
sudo rm -r Gf-Patterns/
wget https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json
mv potential.json ~/.gf
git clone https://github.com/KathanP19/JSFScan.sh.git
cd JSFScan
sudo chmod +x install.sh
bash install.sh
cd ../
git clone https://github.com/dark-warlord14/JSScanner.git
cd JSScanner
chmod +x install.sh
bash install.sh
cd ../
git clone https://github.com/OdinF13/Bug-Bounty-Scripts.git
go get -u github.com/tomnomnom/qsreplace
git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
cd ../
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pytho3 setup.py install
pip3 install -r requirements.txt
cd ../
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
pip3 install -r requirements.txt
cd ../
go get -u github.com/hahwul/dalfox
go get -u github.com/jaeles-project/gospider
go get -u github.com/vsec7/urlive
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap













GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/cmd/subfinder;
go get github.com/tomnomnom/hacks/waybackurls;
GO111MODULE=on go get -u -v github.com/hahwul/dalfox;
go get github.com/manasmbellani/subjack
