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
echo -e "${NORMAL}${BOLD}\nStarting Subdomain scan using AssetFinder,Sublist3r,Subfinder,Amass on ${RED}$1${NORMAL}${BOLD}... \n"
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Assetfinder${NORMAL} on $1..."
assetfinder --subs-only $1 |sort -u > $2-assetfinder.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Sublist3r${NORMAL} on $1..."
python3 ~/tools/Sublist3r/sublist3r.py -d $1 -o $2-sublister.txt > /dev/null
sleep 2

echo -e "${NORMAL}Starting ${GREEN}SubFinder${NORMAL} on $1..."
subfinder -d $1 -o $2-subfinder.txt > /dev/null
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Amass${NORMAL} on $1..."
amass enum --passive -d $1 -o $2-amass.txt
sleep 2

echo -e "${NORMAL}${BOLD}\nSubdomain Scan Finished starting HTTPX & Filtering ${RED}$1${NORMAL}${BOLD}... \n"
sleep 2

echo -e "${BOLD}\nCombining and Filtering Unique Subdomains in Target-finalsubdomains.txt ${RED}$1... \n ${NORMAL} "
cat $2-sublister.txt $2-assetfinder.txt $2-subfinder.txt $2-amass.txt | grep -v "*" |sort -u > $2-finalsubdomains.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}HTTPx${NORMAL} on all filtered subdomains..."
cat $2-finalsubdomains.txt | sort -u | uniq -u | httpx -silent > $2-alive.txt
sleep 2


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

echo -e "${NORMAL}Starting ${GREEN}NMAP${NORMAL} on alive domains..."
mkdir nmapoutput
for domain in $(cat $2-finalsubdomains.txt)
do
        nmap -sC -sV -v $domain | tee nmapoutput/$domain
done
sleep 2

echo -e "${NORMAL}Finished Takeover ${GREEN}Getting CNames,Title,Statuscodes & IP${NORMAL} ..."
cat $2-alive.txt | httpx -silent -title -status-code -cname -ip| tr "[]" " " > $2-httpxoverview.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei CVE Scan${NORMAL} alive domains after updating templates..."
nuclei -update-templates
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/cves -o $2-nucleicves.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Tokens Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/tokens -o $2-nucleiTokens.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Default Credentials Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/default-credentials -o $2-nucleiDefaultCred.txt
sleep 2

echo -e "${NORMAL}${BOLD}Starting ${GREEN}Waybackurls${NORMAL}${BOLD} param output on $1... ${NORMAL} "
cat $2-finalsubdomains.txt | waybackurls > $2-waybackurls.txt
sleep 2

#echo -e "${NORMAL}${BOLD}Starting ${GREEN}Gospider${NORMAL}${BOLD} param output on $1... ${NORMAL} "
#gospider -S $2-finalsubdomains.txt -o $2-gospider -c 10 -d 1 && grep -r -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" outdir | sort -u | tee $2-gospider.txt


echo -e "${NORMAL}${BOLD}Starting ${GREEN}Gau (Get all Urls)${NORMAL}${BOLD} param output on $1... ${NORMAL} "
sleep 2
cat $2-finalsubdomains.txt | gau > $2-gau.txt
sort -u $2-waybackurls.txt $2-gau.txt > $2-allurls.txt #Combining Results of Gospider,Wayback,Gau

echo -e "Starting ${GREEN}XSS${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf xss > $2-xss.txt

echo -e "Starting ${GREEN}SSRF${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf ssrf > $2-ssrf.txt

echo -e "Starting ${GREEN}SSTI${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf ssti > $2-ssti.txt

echo -e "Starting ${GREEN}REDIRECT${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf redirect > $2-redirect.txt

echo -e "Starting ${GREEN}SQLi${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf sqli > $2-sqli.txt

echo -e "Starting ${GREEN}LFI${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf lfi > $2-lfi.txt

echo -e "Starting ${GREEN}RCE${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf rce > $2-rce.txt

echo -e "Starting ${GREEN}IDOR${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf idor > $2-idor.txt

echo -e "Starting ${GREEN}AWS S3 Buckets${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf s3-buckets | tee -a $2-s3buckets.txt

echo -e "Starting ${GREEN}PHP Errors${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf php-errors | tee -a $2-Phperrors.txt


echo -e "Starting ${GREEN}AWS Keys${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf aws-keys | tee -a $2-awskeys.txt

find . -type f -size 0 -delete
echo -e "${BOLD}\nAll your outputs are saved in ${GREEN}$2/ \n"