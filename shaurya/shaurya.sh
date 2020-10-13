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
cat $2-sublister.txt $2-assetfinder.txt $2-subfinder.txt $2-amass.txt | grep -v "*" |sort -u > $2-finalsubdomains.txt
sleep 2

echo -e "${NORMAL}${BOLD}\nSubdomain Scan Finished starting HTTPX & Filtering $1${NORMAL}${BOLD}... \n"
sleep 2

echo -e "${NORMAL}Starting ${GREEN}HTTPx${NORMAL} on all filtered subdomains..."
cat $2-finalsubdomains.txt | sort -u | uniq -u | httpx -silent -follow-redirects | sort -u | uniq -u > $2-alive.txt
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

echo -e "${NORMAL}Starting ${GREEN}Nuclei CVE Scan${NORMAL} alive domains after updating templates..."
nuclei -update-templates
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/cves -o $2-nucleiCVES.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Tokens Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/tokens -o $2-nucleiTokens.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Vulnerablities Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/vulnerabilities -o $2-nucleiVulnerabilities.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Files Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/files -o $2-nucleiFiles.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Basic LFI Fuzzing Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/fuzzing -o $2-nucleiLfi.txt
sleep 2

echo -e "${NORMAL}Starting ${GREEN}Nuclei Default Credentials Scan on ${NORMAL} alive domains"
cat $2-alive.txt | nuclei -t ~/tools/nuclei-templates/default-credentials -o $2-nucleiDefaultCred.txt
sleep 2

echo -e "${NORMAL}${BOLD}Starting ${GREEN}Waybackurls${NORMAL}${BOLD} param output on $1... ${NORMAL} "
cat $2-alive.txt | waybackurls | tee $2-waybackurls.txt
sleep 2

#echo -e "${NORMAL}${BOLD}Starting ${GREEN}Gospider${NORMAL}${BOLD} param output on $1... ${NORMAL} "
#gospider -S $2-finalsubdomains.txt -o $2-gospider -c 10 -d 1 && grep -r -o -E "(([a-zA-Z][a-zA-Z0-9+-.]*\:\/\/)|mailto|data\:)([a-zA-Z0-9\.\&\/\?\:@\+-\_=#%;,])*" outdir | sort -u | tee $2-gospider.txt
echo -e "${NORMAL}${BOLD}Starting ${GREEN}Hackcrawler${NORMAL}${BOLD} param output on $1... ${NORMAL} "
cat $2-alive.txt | hakrawler | tee $2-hakrawler.txt
sleep 2

echo -e "${NORMAL}${BOLD}Starting ${GREEN}Gau (Get all Urls)${NORMAL}${BOLD} param output on $1... ${NORMAL} "
sleep 2
cat $2-alive.txt | gau | tee $2-gau.txt
cat $2-waybackurls.txt $2-gau.txt $2-hakrawler.txt | sort -u | uniq -u | $2-allurls.txt #Combining Results of Gospider,Wayback,Gau


#echo -e "Starting ${GREEN}Dalfox${NORMAL} for XSS on $1... ${NORMAL}"
#gospider -S $2-alive.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" -a | grep -e "code-200" | awk '{print $5}' | grep -v ".js?ver=" | grep -v ".js?version=" | grep -v ".css?ver=" | grep "=" | qsreplace -a | dalfox pipe -blind randommeet.xss.ht -o $2-dalfoxXSSgospider.txt
#cat $2-allurls.txt | grep -v ".js?ver=" | grep -v ".css?ver=" | grep -v ".js?version=" | grep "=" | qsreplace -a | dalfox pipe -blind randommeet.xss.ht -o $2-dalfoxXSSgauway.txt
#sleep 2

echo -e "Starting ${GREEN}Kxss${NORMAL} for XSS on $1... ${NORMAL}"
cat $2-allurls.txt | kxss > $2-kxss.txt


echo -e "Starting ${GREEN}REDIRECT${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf redirect > $2-redirect.txt


echo -e "Starting ${GREEN}AWS S3 Buckets${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf s3-buckets | sort -u | uniq -u | tee -a $2-s3buckets.txt

echo -e "Starting ${GREEN}AWS Keys${NORMAL} param filtering on $1... ${NORMAL} "
sleep 2
cat $2-allurls.txt | gf aws-keys | tee -a $2-awskeys.txt

find . -type f -size 0 -delete
echo -e "${BOLD}\nAll your outputs are saved in ${GREEN}$2/ \n"