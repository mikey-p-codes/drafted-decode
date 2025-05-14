# Catch OOB Reads and Decode b64 in one shot
## decoder.py

Python Script to run http.server on a port of your choosing, catch a cURL command with base64 encoded data and decode the data right in the terminal.  Eliminate the need to copy responses and pipe to base64 -d.  

**Note** When using this with a certain HTB challenge, I did notice that not all requests from the victim machine were coming to me. Based on the vulnerabilty I was exploiting, it might have just been the way the intentionally vulnerable code was designed. However,  I modified the script to stop the server from sending responses and it seemed to produce better results.  In a CTF its probably okay, but if you are planning to use this for bug bounty it might be useful to try and return some sort of User Agent that identifies you.  

```bash
python3 decoder.py -h
Usage: python3 base64-listener.py [port]

python3 decoder.py 9001
[*] Base64 Listener started on port 9001
[*] Make sure YOUR_IP is accessible by the target.
[*] Waiting for incoming Base64 encoded data in URL paths...

--- Received Base64 String from 10.129.175.110 ---
PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KPHRpdGx[...snip...]+CjwvaHRtbD4K
--- Decoded Content ---
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
```
