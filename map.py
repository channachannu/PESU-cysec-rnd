import os
import sys
import nmap
try:
    nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

#print("Enter the Domain/IP address")
#ID = raw_input()
ID = sys.argv[1]
nm.scan(hosts=ID,arguments='-Pn -A -O -v')
nm.scaninfo()	
print("\n----------------------------\n")
#print(nm.csv())
host_lists = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host,status in host_lists:
	if status=="up":
		print('----------------------------------------------------')
		print('Host : {0} ({1})'.format(host, nm[host].hostname()))
		print('State : {0}'.format(nm[host].state()))
		nm.scan(host, arguments="-O")
    		if 'osmatch' in nm[host]:
			for osmatch in nm[host]['osmatch']:
				print('OsMatch.name : {0}'.format(osmatch['name']))
			    	print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
			    	print('OsMatch.line : {0}'.format(osmatch['line']))
				if 'osclass' in osmatch:
					for osclass in osmatch['osclass']:
					    print('OsClass.type : {0}'.format(osclass['type']))
					    print('OsClass.vendor : {0}'.format(osclass['vendor']))
					    print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
					    print('OsClass.osgen : {0}'.format(osclass['osgen']))
					    print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
		print('----------------------------------------------------')
		if 'fingerprint' in nm[host]:
        		print('Fingerprint : {0}'.format(nm['host']['fingerprint']))		    
		print('Protocols : {0}'.format(nm[host].all_protocols()))
		for proto in nm[host].all_protocols():
		  	print('----------')
	       		print('Protocol : %s' % proto)
	 
		 	lport = nm[host][proto].keys()
		 	lport.sort()
		 	for port in lport:
		     		print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
		
