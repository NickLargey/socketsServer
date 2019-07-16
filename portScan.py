import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgthost, tgtport):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgthost, tgtport))
		connSkt.send('Hello\r\n')

		results = connSkt.recv(100)
		screenLock.acquire()
		print('[+] ' + str(tgtport) + ' tcp open')

	except:
		screenLock.acquire()
		print('[-] ' + str(tgtport) + ' tcp closed')

	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgthost, tgtports):
	try:
		tgtIP = gethostbyname(tgthost)
	except:
		print('[-] Can not resolve ' + tgthost + ': Unknown host')
		return

	try:
		tgtName = gethostbyaddr(tgtIP)
		print('\n[+] Scan results for: ' + tgtName[0])
	except:
		print('\n[-] Scan results for: ' + tgtIP)

	setdefaulttimeout(1)

	for tgtport in tgtports:
		t = Thread(target=connScan, args=(tgthost, int(tgtport)))
		t.start()

def main():
	parser = optparse.OptionParser('usage %prog -h <target host>' +
									'-p <target port>')
	parser.add_option('-H', dest='tgthost', type='string')
	parser.add_option('-P', dest='tgtport', type='string')
	options, args = parser.parse_args()
	if options.tgthost == None or options.tgthost == None:
		print(parser.usage)
		exit(0)
	else:
		tgthost = options.tgthost
		tgtports = str(options.tgtport).split(',')

	portScan(tgthost, tgtports)

if __name__ == '__main__':
	main()