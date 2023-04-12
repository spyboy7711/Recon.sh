#!/bin/bash

test_s(){




		
		echo "Scan startted for $1" | notify

		mkdir $1
		mkdir $1/subs
		mkdir $1/nuclear

		echo "[1] Subfinder..."
		subfinder -d $1 -o $1/subs/$1-subdomain.txt -silent  >> /dev/null  #use 3rd part api keys

		echo "[2] Assetfinder..."
		#figlet "Assetfinder"
		assetfinder -subs-only $1 >> $1/subs/$1-assetfinder.txt   #Randomly genrates subdomains

		echo "[3] Findomain..."
		#figlet "Findomain"
		findomain -q -t $1 >> $1/subs/$1-findomain.txt  #use 3rd part api keys

		echo "[4] Ctfr..."
		#figlet "Ctfr"
		python3 /root/tools/ctfr/ctfr.py -d $1 -o $1/subs/$1-Ctfr.txt >> /dev/null  #Using SSL cert record

		echo "[5] Gauplus..."
		#figlet "Gauplus"
		gauplus -t 5 -random-agent -subs $1 |  unfurl -u domains | anew -q $1/subs/$1-Gauplus.txt  # Using historical urls 

		echo "[6] Waybackurls" 
		#figlet "Waybackurls"
		waybackurls $1 |  unfurl -u domains | anew -q $1/subs/$1-waybackurls.txt # Using historical urls 

		echo "[7] Github-subdomains"
		github-subdomains -d $1 -t /root/.config/github/tokens.txt -o $1/subs/$1-github-subdomains.txt >> /dev/null # Using git hub token it will find subdomains from github code

		echo "[8] Crobat"
		#figlet "crobat"
		crobat -s $1 > $1/subs/$1-crobat.txt        # finds sub using project sonar
		echo "[9] Puredns"                                                                   #here you have to create resolvers manualy
		puredns bruteforce /root/tools/word-lists/all.txt $1 --wildcard-batch 1000000 -r /root/.config/dnsvalidator/resolvers.txt -q | anew -q $1/subs/$1-Puredns.txt  # bruteforcing

		echo "[10] analyticsrelationships"
                echo $i
		python3 /root/tools/AnalyticsRelationships/Python/analyticsrelationships.py -u https://$1 > $1/subs/$1-analyticsrelationships_test.txt  # findsubdomains using Google Analytics
		cat $1/subs/$1-analyticsrelationships_test.txt | sed 's/|__ //' > $1/subs/$1-analyticsrelationships.txt
		rm -r $1/subs/$1-analyticsrelationships_test.txt

		cat $1/subs/$1-subdomain.txt | anew -q $1/test.txt
		cat $1/subs/$1-assetfinder.txt | anew -q $pppp1/test.txt 
		cat $1/subs/$1-findomain.txt | anew -q $1/test.txt 
		cat $1/subs/$1-Ctfr.txt | anew -q $1/test.txt 
		cat $1/subs/$1-Gauplus.txt | anew -q $1/test.txt
		cat $1/subs/$1-waybackurls.txt | anew -q $1/test.txt
		cat $1/subs/$1-github-subdomains.txt | anew -q $1/test.txt
		cat $1/subs/$1-crobat.txt | anew -q $1/test.txt
		cat $1/subs/$1-Puredns.txt | anew -q $1/test.txt
		cat $1/subs/$1-analyticsrelationships.txt | anew -q $1/test.txt

		echo "[11] DNScewl"
		DNScewl --tL $1/test.txt -p /root/word-lists/subs/permutations_list.txt --level=0 --subs --no-color | tail -n +14  > $1/subs/$1-permutations.txt  #here you have to create resolver manualy 
		puredns resolve $1/subs/$1-permutations.txt -r /root/.config/dnsvalidator/resolvers.txt -q | anew -q $1/subs/$1-DNScewl.txt                              # trys conbination by using above subdomains

		cat $1/subs/$1-DNScewl.txt | anew -q $1/test.txt 

		echo "[12] Httpx"
		figlet "Httpx"
		cat $1/test.txt | httpx -silent >> $1/final-sub.txt
		cat $1/test.txt | httpx -silent -mc 403,401 >> $1/403.txt
		cat $1/test.txt | httpx -silent -mc 200 >> $1/200.txt
		cat $1/test.txt | httpx -silent -mc 301 >> $1/301.txt
		
		echo "Alive subdomains : `cat $1/final-sub.txt | wc -l`" | notify -silent
		echo "subdomains with 200 status : `cat $1/200.txt | wc -l`" | notify -silent
		echo "subdomains with 301 status : `cat $1/301.txt | wc -l`" | notify -silent
		echo "subdomains with 403 status : `cat $1/403.txt | wc -l`" | notify -silent
}

test_m(){ 

		test_s $1

		echo "[13] Subdomain Takeover"
		#figlet "Takeover"
		subjack -w $1/test.txt -t 1000 -o $1/subjack.txt   
		cat $1/subjack.txt | notify -silent

		echo "[14] Nuclei"
		figlet "Nuclear"
		nuclei -l $1/final-sub.txt -silent -t /root/nuclei-templates/ -o $1/nuclear/output.txt
		cat $1/nuclear/output.txt | egrep -i "(critical|high|medium|low)" | notify -silent
		#awk '{print $3 "\t" "\t" $5 "\t" $6 "\t" $7}' $1/nuclear/output.txt | grep -v info > $1/nuclear/telegramout.txt #Sorting and removing informational bugs
		#while read -r line
		#do
		#curl "https://api.telegram.org/bot5772481990:AAEG5CfPusfyLTHrw7ac35iPVDi-HYcyJuc/sendMessage?chat_id=-730130301&text=$(urlencode $line)" #calling telegram api to send message
		#done < $1/nuclear/telegramout.txt


		
		echo "[15] Naabu"
		#figlet "Naabu"
		naabu -list $1/test.txt -silent >> $1/naabu.txt
		echo -e "Port scan :  \n`cat $1/naabu.txt`" | notify -silent

		#echo "[14] Http Request Smuggler"
		#cp -r /root/tools/smuggler $1/
		#cat $1/final-sub.txt | python3 /$1/smuggler/smuggler.py -q -x
		#mv /$1/smuggler/payloads smuggled
		#rm -r /$1/smuggler
}

test_a(){


		test_m $1
	cat $1/200.txt | unfurl -u domains | anew -q $1/200-domains.txt # is it redudant?
	mkdir $1/scanned_domains
	for i in `cat $1/200-domains.txt`
		do 

		#echo "$i" > $i/domains.txt
		#echo "."
		#echo "."
		#echo "."
		#echo "."
		#echo "Scan started for $i"

		
		mkdir $1/scanned_domains/$i
		mkdir $1/scanned_domains/$i/js-secrets
		mkdir $1/scanned_domains/$i/test
		echo "[16] Waybackurls"
		#figlet "Waybackurls"
		echo "[-] waybackurls started crawling" 
		waybackurls $i > $1/scanned_domains/$i/wayback.txt        # get urls
		echo "[+] waybackurls completed crawling"

		echo "[17] Gau"
		#figlet "Gau"
		echo "[-] gau started crawling" 
		gau $i > $1/scanned_domains/$i/gau.txt                # get urls
		echo "[+] gau completed crawling" 
		
		#echo "[18] Gospider"
		#figlet "Gau"
		#echo "[-] Gospider started crawling" 
		#gospider -a -d 3 -t 3 -c 50 -s https://$i | tr "[] " "\n" | grep -oE "(/\*([^*]|(\*+[^*/]))*\*+/)|(.*)|(//.*)" | httpx -silent -threads 800 -o $1/scanned_domains/$i/gospider-urls.txt
		#echo "[+] Gospider completed crawling"                 # get urls by crawling 
 
		echo "[19] Filtering MIME type"
		#figlet "Filtered_urls pattern"
		 
		mkdir $1/scanned_domains/$i/Filtered_urls
		cat $1/scanned_domains/$i/wayback.txt | grep "=" | egrep -iv ".(jpg|jpeg|css|gif|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" >> $1/scanned_domains/$i/Filtered_urls/wayback.txt
		cat $1/scanned_domains/$i/gau.txt | grep "=" | egrep -iv ".(jpg|jpeg|css|gif|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" >> $1/scanned_domains/$i/Filtered_urls/gau.txt #Filtering MIME files

		cat $1/scanned_domains/$i/Filtered_urls/wayback.txt | grep "=" | qsreplace -a >> $1/scanned_domains/$i/test/1.txt
		cat $1/scanned_domains/$i/Filtered_urls/gau.txt | grep "=" | qsreplace -a >> $1/scanned_domains/$i/test/2.txt
		cat $1/scanned_domains/$i/test/1.txt | anew -q $1/scanned_domains/$i/final-urls.txt
		cat $1/scanned_domains/$i/test/2.txt | anew -q $1/scanned_domains/$i/final-urls.txt

		cat $1/scanned_domains/$i/wayback.txt | anew -q $1/scanned_domains/$i/combo.txt
		cat $1/scanned_domains/$i/wayback.txt | anew -q $1/scanned_domains/$i/combo.txt
		echo "[-] Filtering of MIME files completed"

		echo "[20] GF pattern"
		#figlet "GF pattern"
		echo "[-] GF pattern started"
		mkdir $1/scanned_domains/$i/GF
		cat $1/scanned_domains/$i/combo.txt | gf xss >> $1/scanned_domains/$i/GF/final-xss.txt
		cat $1/scanned_domains/$i/combo.txt | gf ssrf >> $1/scanned_domains/$i/GF/final-ssrf.txt
		cat $1/scanned_domains/$i/combo.txt | gf idor >> $1/scanned_domains/$i/GF/final-idor.txt
		cat $1/scanned_domains/$i/combo.txt | gf ssti >> $1/scanned_domains/$i/GF/final-ssti.txt
		cat $1/scanned_domains/$i/combo.txt | gf redirect >> $1/scanned_domains/$i/GF/final-redirect.txt        #Use GF pattern
		cat $1/scanned_domains/$i/combo.txt | gf rce >> $1/scanned_domains/$i/GF/final-rce.txt
		#cat $1/scanned_domains/$i/combo.txt | gf Sqli >> $1/scanned_domains/$i/GF/final-Sqli.txt
		cat $1/scanned_domains/$i/combo.txt | gf LFI >> $1/scanned_domains/$i/GF/final-LFI.txt
		#cat $1/scanned_domains/$i/combo.txt | gf debug_logic >> $1/scanned_domains/$i/GF/final-debug_logic.txt
		echo "[+] GF pattern completed"

		


		#for jsFile in 'cat subjsUrls.txt'
		#do

		#python3 /root/tools/SecretFinder/SecretFinder.py -i $jsFile | tee -a secrets.txt secrets_from.txt

		#echo -e "\n\n" | tee -a secrets_from.txt
		#done



		echo "[21] KXSS"
		#figlet "KXSS"
		echo "[-] kxss scan started"
		mkdir $1/scanned_domains/$i/kxss
		cat $1/scanned_domains/$i/final-urls.txt | kxss >> $1/scanned_domains/$i/kxss/final-kxss.txt         # check if paramters vaule if filtered
		echo "[+] kxss scan completed"

		echo "[22] Dalfox"
		#figlet "Dalfox"
		echo "[-] Dalfox Scan started"
		mkdir $1/scanned_domains/$i/final
		cat $1/scanned_domains/$i/final-urls.txt | dalfox pipe -b https://xploita.xss.ht -o $1/scanned_domains/$i/final/xss-dalfox.txt 
		cat $1/scanned_domains/$i/final/xss-dalfox.txt | notify -silent       # Finds XSS 
		echo "[+] Dalfox Scan completed"

		echo "[23]JS-SCAN"
		#figlet "JS-SCAN"
		echo "I like to eat js files"

		cat $1/scanned_domains/$i/final-urls.txt | grep "\.js" >> $1/scanned_domains/$i/js-secrets/subjsUrls.txt
		
		#cat $1/scanned_domains/$i/gospider-urls.txt | grep "$i" | subjs -c 100 -t 5 | anew -q $1/scanned_domains/$i/js-secrets/subjsUrls.txt

		for jsFile in `cat $1/scanned_domains/$i/js-secrets/subjsUrls.txt`
		do
		echo -e "$jsFile ==>" | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt

		python3 /root/tools/LinkFinder/linkfinder.py -o cli -i $jsFile | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints.txt $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt     # Finds links and directorys in js files
		python3 /root/tools/SecretFinder/SecretFinder.py -i $jsFile | tee -a $1/scanned_domains/$i/js-secrets/secrets.txt $1/scanned_domains/$i/js-secrets/secrets_from.txt
		echo -e "\n\n" | tee -a $1/scanned_domains/$i/js-secrets/newEndpoints_from.txt                                                            #Find creadintials in js files
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
		  -s   for only subdomain enumeration
		       
		  -m   for medium level scan [subdomain Enumeration, subdomain Takeover, probing_Domains, port scanning, nuclei_Scanning]
		       
		  -a   for advance level scan [subdomain Enumeration, subdomain Takeover, wayback_Urls, probing_Domains, nuclei_Scanning, port scanning, xss scan, Js Scan]
		       
		";
	    ;;
	  * ) echo "Invalid Options $OPTARG require an argument";
	    ;;
	esac
done
shift $((OPTIND -1))
