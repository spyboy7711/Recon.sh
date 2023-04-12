#!/bin/bash


test_s(){




	                                                                                                                                                               Code by @SPY8OY  "


		figlet "Lazy Recon"
		echo "Scan startted for $1"

		mkdir $1
		mkdir $1/subs
		mkdir $1/nuclear

		echo "[1] Subfinder..."
		subfinder -d $1 -o $1/subs/$1-subdomain.txt -silent  >> /dev/null

		echo "[2] Assetfinder..."
		#figlet "Assetfinder"
		assetfinder -subs-only $1 >> $1/subs/$1-assetfinder.txt

		echo "[3] Findomain..."
		#figlet "Findomain"
		findomain -q -t $1 >> $1/subs/$1-findomain.txt

		echo "[4] Ctfr..."
		#figlet "Ctfr"
		python3 /root/tools/ctfr/ctfr.py -d $1 -o $1/subs/$1-Ctfr.txt >> /dev/null

		echo "[5] Gauplus..."
		#figlet "Gauplus"
		gauplus -t 5 -random-agent -subs $1 |  unfurl -u domains | anew -q $1/subs/$1-Gauplus.txt

		echo "[6] Waybackurls" 
		#figlet "Waybackurls"
		waybackurls $1 |  unfurl -u domains | anew -q $1/subs/$1-waybackurls.txt

		echo "[7] Github-subdomains"
		github-subdomains -d $1 -t /root/.config/github/tokens.txt -o $1/subs/$1-github-subdomains.txt >> /dev/null

		echo "[8] Crobat"
		#figlet "crobat"
		crobat -s $1 > $1/subs/$1-crobat.txt
		echo "[9] Puredns"
		puredns bruteforce /root/tools/wordlist/all.txt $1 --wildcard-batch 1000000 -r /root/.config/dnsvalidator/resolvers.txt -q | anew -q $1/subs/$1-Puredns.txt 

		#echo "[10] analyticsrelationships"
		#python3 /root/tools/AnalyticsRelationships/Python/analyticsrelationships.py -u https://$1 | anew -q $1/subs/$1-analyticsrelationships_test.txt
		#cat $1/subs/$1-analyticsrelationships_test.txt | sed 's/|__ //' > $1/subs/$1-analyticsrelationships.txt
		#rm -r $1/subs/$1-analyticsrelationships_test.txt

		cat $1/subs/$1-subdomain.txt | anew -q $1/test.txt
		cat $1/subs/$1-assetfinder.txt | anew -q $1/test.txt 
		cat $1/subs/$1-findomain.txt | anew -q $1/test.txt 
		cat $1/subs/$1-Ctfr.txt | anew -q $1/test.txt 
		cat $1/subs/$1-Gauplus.txt | anew -q $1/test.txt
		cat $1/subs/$1-waybackurls.txt | anew -q $1/test.txt
		cat $1/subs/$1-github-subdomains.txt | anew -q $1/test.txt
		cat $1/subs/$1-crobat.txt | anew -q $1/test.txt
		cat $1/subs/$1-Puredns.txt | anew -q $1/test.txt
		#cat $1/subs/$1-analyticsrelationships.txt | anew -q $1/test.txt

		echo "[10] DNScewl"
		DNScewl --tL $1/test.txt -p /root/tools/wordlist/subs/permutations_list.txt --level=0 --subs --no-color | tail -n +14  > $1/subs/$1-permutations.txt
		puredns resolve $1/subs/$1-permutations.txt -r /root/.config/dnsvalidator/resolvers.txt -q | anew -q $1/subs/$1-DNScewl.txt

		cat $1/subs/$1-DNScewl.txt | anew -q $1/test.txt 

		echo "[11] Httpx"
		figlet "Httpx"
		cat $1/test.txt | httpx -silent >> $1/final-sub.txt
		cat $1/test.txt | httpx -silent -mc 403,401 >> $1/403.txt
		cat $1/test.txt | httpx -silent -mc 200 >> $1/200.txt
		cat $1/test.txt | httpx -silent -mc 301 >> $1/301.txt
}

test_m(){ 

		test_s $1

		echo "[12] Subdomain Takeover"
		#figlet "Takeover"
		nuclei -l $1/test.txt -silent -t takeovers/ -o $1/takeover.txt
		subzy -targets $1/test.txt > $1/subzy.txt

		echo "[13] Nuclei"
		#echo "It's not a nuclei its Nuclear Bomb"
		#figlet "Nuclear"

		echo "[+]Scanning for default-logins "
		nuclei -l $1/final-sub.txt -silent -t default-logins/ -o $1/nuclear/default-logins.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for exposures "
		nuclei -l $1/final-sub.txt -silent -t exposures/ -o $1/nuclear/exposures.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for exposures "
		nuclei -l $1/final-sub.txt -silent -t headless/ -o $1/nuclear/headless.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for cves "
		nuclei -l $1/final-sub.txt -silent -t cves/ -o $1/nuclear/cves.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for misconfiguration "
		nuclei -l $1/final-sub.txt -silent -t misconfiguration/ -o $1/nuclear/misconfiguration.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for vulnerabilities "
		nuclei -l $1/final-sub.txt -silent -t vulnerabilities/ -o $1/nuclear/vulnerabilities.txt >> /dev/null
		echo -e ".\n.\nDone"
		echo "[+]Scanning for technologies "
		nuclei -l $1/final-sub.txt -silent -t technologies/ -o $1/nuclear/technologies.txt >> /dev/null
		echo -e ".\n.\nDone"


		
		echo "[14] Naabu"
		#figlet "Naabu"
		naabu -list $1/test.txt -silent >> $1/naabu.txt

		#echo "[14] Http Request Smuggler"
		#cp -r /root/tools/smuggler $1/
		#cat $1/final-sub.txt | python3 /$1/smuggler/smuggler.py -q -x
		#mv /$1/smuggler/payloads smuggled
		#rm -r /$1/smuggler
}

test_a(){

	cat $1/200.txt | unfurl -u domains | anew -q $1/200-domains.txt
	for i in `cat $1/200-domains.txt`
		do 

		#echo "$i" > $i/domains.txt
		#echo "."
		#echo "."
		#echo "."
		#echo "."
		#echo "Scan startted for $i"

		mkdir $1/scanned_domains
		mkdir $1/scanned_domains/$i
		mkdir $1/scanned_domains/$i/js-secrets
		mkdir $1/scanned_domains/$i/test
		echo "[15] Waybackurls"
		#figlet "Waybackurls"
		echo "[-] waybackurls started crawling" 
		waybackurls $i > $1/scanned_domains/$i/wayback.txt
		echo "[+] waybackurls completed crawling"

		echo "[16] Gau"
		#figlet "Gau"
		echo "[-] gau started crawling" 
		gau $i > $1/scanned_domains/$i/gau.txt
		echo "[+] gau completed crawling" 

		echo "[17] Filtering MIME files"
		#figlet "Filtered_urls pattern"
		 
		mkdir $1/scanned_domains/$i/Filtered_urls
		cat $1/scanned_domains/$i/wayback.txt | grep "=" | egrep -iv ".(jpg|jpeg|css|gif|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" >> $1/scanned_domains/$i/Filtered_urls/wayback.txt
		cat $1/scanned_domains/$i/gau.txt | grep "=" | egrep -iv ".(jpg|jpeg|css|gif|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" >> $1/scanned_domains/$i/Filtered_urls/gau.txt

		cat $1/scanned_domains/$i/Filtered_urls/wayback.txt | grep "=" | qsreplace -a >> $1/scanned_domains/$i/test/1.txt
		cat $1/scanned_domains/$i/Filtered_urls/gau.txt | grep "=" | qsreplace -a >> $1/scanned_domains/$i/test/2.txt
		cat $1/scanned_domains/$i/test/1.txt | anew -q $1/scanned_domains/$i/final-urls.txt
		cat $1/scanned_domains/$i/test/2.txt | anew -q $1/scanned_domains/$i/final-urls.txt

		cat $1/scanned_domains/$i/wayback.txt | anew -q $1/scanned_domains/$i/combo.txt
		cat $1/scanned_domains/$i/wayback.txt | anew -q $1/scanned_domains/$i/combo.txt
		echo "[-] Filtering of MIME files completed"

		echo "[18] GF pattern"
		#figlet "GF pattern"
		echo "[-] GF pattern started"
		mkdir $1/scanned_domains/$i/GF
		cat $1/scanned_domains/$i/combo.txt | gf xss >> $1/scanned_domains/$i/GF/final-xss.txt
		cat $1/scanned_domains/$i/combo.txt | gf ssrf >> $1/scanned_domains/$i/GF/final-ssrf.txt
		cat $1/scanned_domains/$i/combo.txt | gf idor >> $1/scanned_domains/$i/GF/final-idor.txt
		cat $1/scanned_domains/$i/combo.txt | gf ssti >> $1/scanned_domains/$i/GF/final-ssti.txt
		cat $1/scanned_domains/$i/combo.txt | gf redirect >> $1/scanned_domains/$i/GF/final-redirect.txt
		cat $1/scanned_domains/$i/combo.txt | gf rce >> $1/scanned_domains/$i/GF/final-rce.txt
		#cat $1/scanned_domains/$i/combo.txt | gf Sqli >> $1/scanned_domains/$i/GF/final-Sqli.txt
		cat $1/scanned_domains/$i/combo.txt | gf LFI >> $1/scanned_domains/$i/GF/final-LFI.txt
		#cat $1/scanned_domains/$i/combo.txt | gf debug_logic >> $1/scanned_domains/$i/GF/final-debug_logic.txt
		echo "[+] GF pattern completed"

		


		#for jsFile in `cat subjsUrls.txt`
		#do

		#python3 /root/tools/SecretFinder/SecretFinder.py -i $jsFile | tee -a secrets.txt secrets_from.txt

		#echo -e "\n\n" | tee -a secrets_from.txt
		#done



		echo "[19] KXSS"
		#figlet "KXSS"
		echo "[-] kxss scan started"
		mkdir $1/scanned_domains/$i/kxss
		cat $1/scanned_domains/$i/final-urls.txt | kxss >> $1/scanned_domains/$i/kxss/final-kxss.txt
		echo "[+] kxss scan completed"

		#echo "[5] Arjun"
		#figlet "Arjun"
		#arjun -i $i/final-urls.txt -oT $i/urls.txt

		echo "[20] Dalfox"
		#figlet "Dalfox"
		echo "[-] Dalfox Scan started"
		mkdir $1/scanned_domains/$i/final
		cat $1/scanned_domains/$i/final-urls.txt | dalfox pipe -S -b https://shreyaskoli165.xss.ht -o $1/scanned_domains/$i/final/xss-dalfox.txt
		echo "[+] Dalfox Scan completed"

		echo "[21]JS-SCAN"
		#figlet "JS-SCAN"
		echo "I like to eat js files"

		cat $1/scanned_domains/$i/final-urls.txt | grep "\.js" >> $1/scanned_domains/$i/js-secrets/subjsUrls.txt
		
	gospider -a -d 4 -t 3 -c 50 -s https://$i | tr "[] " "\n" | grep -oE "(/\*([^*]|(\*+[^*/]))*\*+/)|(.*)|(//.*)" | httpx -silent -threads 200 | subjs -c 100 -t 5 | grep "$i" | anew -q $1/scanned_domains/$i/js-secrets/subjsUrls.txt

		for jsFile in `cat $1/scanned_domains/$i/js-secrets/subjsUrls.txt`
		do
		echo -e "$jsFile ==>" | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt

		python3 /root/tools/LinkFinder/linkfinder.py -o cli -i $jsFile | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints.txt $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt
		python3 /root/tools/SecretFinder/SecretFinder.py -i $jsFile | tee -a $1/scanned_domains/$i/js-secrets/secrets.txt $1/scanned_domains/$i/js-secrets/secrets_from.txt
		echo -e "\n\n" | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt
		echo -e "\n\n" | tee -a $1/scanned_domains/$i/js-secrets/secrets_from.txt
		done



		done

}

test_h(){

	echo "you have called H"
}

while getopts ":s:m:a:h" arg; do
  case "$arg" in
  
  	- )      case "${OPTARG}" in

                        esac;;
                        
                        
          s )target=$OPTARG
            test_s $target
            ;;
          m )target=$OPTARG
            test_m $target
            ;;
          a )target=$OPTARG
            test_a $target
            ;;
     	\? | h ) echo "Usage :
		  -s
		       for only subdomain enumeration
		  -m
		       for medium level scan [subdomain Enumeration, subdomain Takeover, probing_Domains, port scanning, nuclei_Scanning]
		  -a
		       for advance level scan [subdomain Enumeration, subdomain Takeover, wayback_Urls, probing_Domains, nuclei_Scanning, port scanning, xss scan, Js Scan]
		";
	    ;;
	  * ) echo "Invalid Options $OPTARG require an argument";
	    ;;
	esac
done
shift $((OPTIND -1))
