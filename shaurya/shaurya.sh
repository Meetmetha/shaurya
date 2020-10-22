#!/bin/bash
#Shaurya by MiteshMetha

if [ -z "$1" ]
  then
    echo "Target domain not supplied"
    echo "Usage : shaurya domain.com outputfoldername"
    exit 1
fi

if [ -z "$2" ]
  then
    echo "Output folder not supplied"
    echo "Usage : shaurya domain.com outputfoldername"
    exit 1
fi

wget -q --spider http://google.com
if [ $? -ne 0 ];then
    echo "Connect to internet before running this tool!"
    exit 1
fi

if [ ! -d "$2" ]; then
        mkdir $2
fi

RED="\e[31m"
BOLD="\e[1m"
NORMAL="\e[0m"
GREEN="\e[92m"

 echo -e ${GREEN}"                    _____ __                                          "
 echo -e ${GREEN}"                   / ___// /_  ____ ___  _________  _______           "
 echo -e ${GREEN}"                   \__ \/ __ \/ __ / / / / ___/ / / / __ /            "
 echo -e ${GREEN}"                  ___/ / / / / /_/ / /_/ / /  / /_/ / /_/ /           "
 echo -e ${GREEN}"                 /____/_/ /_/\__,_/\__,_/_/   \__, /\__,_/            "
 echo -e ${GREEN}"                                             /____/                   "
 echo -e ${GREEN}"                                                                      "
echo -e "${NORMAL}${BOLD}\n                           made by ${GREEN}Mitesh Metha${NORMAL}${BOLD} with ${RED}<3"
sleep 2

cd $2/
echo -e "${NORMAL}${BOLD}\nStarting Subdomain scan using AssetFinder,Sublist3r,Subfinder,Amass on $1${NORMAL}${BOLD}... \n"
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Assetfinder${NORMAL} on $1..."
assetfinder --subs-only $1 |sort -u > $2-assetfinder.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Sublist3r${NORMAL} on $1..."
python3 ~/tools/Sublist3r/sublist3r.py -d $1 -o $2-sublister.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}SubFinder${NORMAL} on $1..."
subfinder -d $1 -o $2-subfinder.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Amass${NORMAL} on $1..."
amass enum --passive -d $1 -o $2-amass.txt
sleep 2

echo -e "${BOLD}\nCombining and Filtering Unique Subdomains in Target-finalsubdomains.txt $1... \n ${NORMAL} "
cat $2-sublister.txt $2-assetfinder.txt $2-subfinder.txt $2-amass.txt | sort -u | uniq -u > $2-finalsubdomains.txt
sleep 2



############################################SUBDOMAIN SCAN FINISHED##########################################



echo -e "${NORMAL}Starting ${GREEN}HTTPx${NORMAL} on all filtered subdomains..."
cat $2-finalsubdomains.txt | httpx -silent -follow-redirects | sort -u | uniq -u > $2-alive.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}HTTPx${NORMAL} on all filtered subdomains..."
cat $2-finalsubdomains.txt | while read domain;do dig  $domain;done | tee -a $2-digs.txt
cat $2-digs.txt | grep CNAME > $2-cnames.txt

echo -e "${NORMAL}Starting ${GREEN}Checking Live domains for Subdomain Takeover using Subzy,Subjack,Nuclei${NORMAL} on $1..."
subjack -w $2-finalsubdomains.txt -t 20 -ssl -c ~/tools/fingerprints.json -o $2-subjack.txt
sleep 2
subzy -targets $2-finalsubdomains.txt -hide_fails --verify_ssl -concurrency 20 | sort -u > $2-subzy.txt
sleep 2
nuclei -l $2-alive.txt -t ~/tools/nuclei-templates/subdomain-takeover -o $2-nucleisubover.txt
sleep 2
nuclei -l $2-alive.txt -t ~/tools/nuclei-templates/dns -o $2-nucleidns.txt
sleep 2
cat $2-subjack.txt $2-subzy.txt $2-nucleisubover.txt $2-nucleidns.txt > $2-SubTakeoverPositives.txt
echo -e "${GREEN}Cat error are just Warnings since some tools didnt find subdomain takeover :)"

echo -e "${NORMAL}Eyewitness Snapshot of each Live subdomain ${NORMAL} ..."
python3 ~/tools/EyeWitness/Python/EyeWitness.py -f $2-alive.txt --no-prompt --web --timeout 15 
sleep 2

echo -e "${NORMAL}Naabu Portscan without Cloudflare on Live subdomain ${NORMAL} ..."
cat $2-finalsubdomains.txt | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe > $2-naabuports.txt
sleep 2


###################################Finsihed Playing with Subdomains##########################################




echo -e "${NORMAL}Starting ${GREEN}Nuclei CVE Scan${NORMAL}"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/cves -o $2-nucleiCVES.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Tokens Scan on ${NORMAL}"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/tokens -o $2-nucleiTokens.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Vulnerablities Scan on ${NORMAL}"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/vulnerabilities -o $2-nucleiVulnerabilities.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Files Scan on ${NORMAL}"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/files -o $2-nucleiFiles.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Basic LFI Fuzzing Scan on ${NORMAL}"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/fuzzing -o $2-nucleiLfi.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Default Credentials Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/default-credentials -o $2-nucleiDefaultCred.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Jaeles CVE Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/cves -U $2-alive.txt -o $2-jaelesCVE.txt
#cat $2-alive.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /root/.jaeles/base-signatures -u @ > $2-jaeles.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles Common Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/common -U $2-alive.txt -o $2-jaelesCommon.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles Sensitive Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/sensitive -U $2-alive.txt -o $2-jaelesSensitive.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles probe Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/probe -U $2-alive.txt -o $2-jaelesProbe.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/COMMON Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/common -U $2-alive.txt -o $2-jaelesFuzzCommon.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/CORS Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/cors -U $2-alive.txt -o $2-jaelesFuzzCors.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/CRLF Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/crlf -U $2-alive.txt -o $2-jaelesCRLF.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/LFI Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/lfi -U $2-alive.txt -o $2-jaelesLFI.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/open-redirect Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/open-redirect -U $2-alive.txt -o $2-jaelesOpenRedirect.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/randomfuzz Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/random -U $2-alive.txt -o $2-jaelesRandomFuzz.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/sqli Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/sqli -U $2-alive.txt -o $2-jaelesSqli.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles FUZZ/ssti Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/base-signatures/fuzz/ssti -U $2-alive.txt -o $2-jaelesSsti.txt
sleep 2


echo -e "${NORMAL}Starting ${GREEN}Jaeles PassiveKeys Scan on ${NORMAL} alive domains"
jaeles scan -c 50 -s /root/.jaeles/passives -U $2-alive.txt -o $2-jaelesPassive.txt
sleep 2



###################################Finsihed Nuclei and Jaeles##########################################



echo -e "${NORMAL}${BOLD}Starting ${GREEN}Waybackurls${NORMAL}${BOLD} param output on $1... ${NORMAL} "
cat $2-alive.txt | waybackurls | tee $2-waybackurls.txt
sleep 2

echo -e "${NORMAL}${BOLD}Starting ${GREEN}Gau (Get all Urls)${NORMAL}${BOLD} param output on $1... ${NORMAL} "
sleep 2
cat $2-alive.txt | gau | tee $2-gau.txt
cat $2-waybackurls.txt $2-gau.txt | grep -v .jpg|grep -v .jpeg|grep -v .gif|grep -v .css|grep -v .tif|grep -v .tiff|grep -v .png|grep -v .ttf|grep -v .woff|grep -v .woff2|grep -v .ico|grep -v .pdf|grep -v .svg|grep -v .txt | sort -u | uniq -u | urlive -c 50 -o $2-allurls.txt #Combining Results of Wayback,Gau


###################################Fetched ALL URLS##########################################


echo -e "Starting ${GREEN}RCE${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf rce > $2-rce.txt


echo -e "Starting ${GREEN}Interesting Params${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf interestingparams > $2-interestingparams.txt

echo -e "Starting ${GREEN}Debug File GF Pattern${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf debug_logic > $2-debug_logic.txt


echo -e "Starting ${GREEN}JS Link Finding${NORMAL} for on $1... ${NORMAL}"
subjs -i $2-allurls.txt > $2-jsfiles

echo -e "Starting ${GREEN}XSS without GF via qsreplace${NORMAL} on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt |grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done | tee -a $2-XSSqsreplace.txt

echo -e "Starting ${GREEN}SSTI qsreplace${NORMAL} on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt |grep '=' | qsreplace "xssfound{{7*7}}"  | httpx -match-regex 'xssfound81' -threads 300 -http-proxy http://127.0.0.1:8080 | tee -a $2-SSTIqsreplace.txt

echo -e "Starting ${GREEN}XSS oneliner with Dalfox${NORMAL} on $1... ${NORMAL} "
sleep 2
gospider -S $2-alive.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o $2-XSSDalfox.txt

echo -e "Starting ${GREEN}SQLInjection Check${NORMAL} for on $1... ${NORMAL}"
cat $2-allurls.txt |grep '=' |qsreplace "' OR '1" | httpx -silent -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n" > $2-sqlinjection.txt

find . -type f -size 0 -delete
echo -e "${BOLD}\nAll your outputs are saved in ${GREEN}$2/ \n"