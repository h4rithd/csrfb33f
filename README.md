```
usage: python3 csrfb33f.py -u [url] -w [wordlist] -c [token-name]

-------------------------------------------------------------
------------ | Brute-force CSRF |----------------------------
-------------------------------------------------------------
                __ _      _____  _____  __
               / _| |    |____ ||____ |/ _|
  ___ ___ _ __| |_| |__      / /    / / |_
 / __/ __| '__|  _| '_ \     \ \    \ \  _|
| (__\__ \ |  | | | |_) |.___/ /.___/ / |
 \___|___/_|  |_| |_.__/ \____/ \____/|_|
                                      V 0.1
by h4rith.com
-------------------------------------------------------------

[!] Required arguments:
  -u , --url           Target URL
  -w , --wordlist      Wordlist path
  -c , --token         CSRF token name

[!] Optional arguments:
  -user , --username   Username

---------------- Script from h4rithd.com ----------------

Example : python3 csrfb33f.py -u http://127.0.0.1/index.php -c csrf_token -w /usr/share/seclists/Passwords/darkweb2017-top100.txt -user admin

```
