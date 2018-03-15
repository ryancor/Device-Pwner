from scapy.all import *
from bluetooth import *
from bt_proximity import BluetoothRSSI
import time
import sys
import math

def calc_dist(dev, num):
	btrssi = BluetoothRSSI(dev)
	n = 1.5    #Path loss exponent(n) = 1.5
    	c = 10   #Environment constant(C) = 10
    	A0 = 2   #Average RSSI value at d0
    	actual_dist = 37   #Static distance between transmitter and Receiver in cm
    	sum_error = 0
    	count = 0

	for i in range(0, num):
		rssi_bt = float(btrssi.get_rssi())
		if (i > 10):
			count = count + 1
			x = float((rssi_bt-A0)/(-10*n))
			distance = (math.pow(10,x) * 100) + c
			error = abs(actual_dist - distance)
            		sum_error = sum_error + error
            		avg_error = sum_error/count

			print("[+] Average Error=  " + str(avg_error))
            		print("[+] Error=  " + str(error))
            		print("[+] Approximate Distance:" + str(distance))
            		print("[+] RSSI: " + str(rssi_bt))
            		print("[+] Count: " + str(count))

		time.sleep(1)
	

def scan():
	devlist = discover_devices()

	if devlist:
		for device in devlist:
			name = str(lookup_name(device))
			print("[+] Found Bluetooth Device %s" % str(name))
			print("[+] MAC Address: %s" % str(device))
			
			calc_dist(str(device), 30)

			print("Now we have distance... Let's spoof this address of %s", str(device))

	else:
			print("[-] No devices found syncing in your area.")

def retBTaddr(addr):
	# Removing null bytes and concat the MAC address
	btAddr = str(hex(int(addr.replace(':', ''), 16) + 1))[2:]

	# Concat everything back to valid MAC
	btAddr = btAddr[0:2] + ":" + btAddr[2:4] + ":" + btAddr[4:6] + ":" + btAddr[6:8] + ":" + btAddr[8:10] + ":" + btAddr[10:12]

	return btAddr

def checkBluetooth(btAddr):
	# >>> btName == '40-9c-28-da-e8-c4'
	# Looks up to see valid address if exists
	btName = lookup_name(btAddr)

	if btName:
		print('[+] Detected Bluetooth Device: %s' % btName) 
	else:
		print('[-] Failed to Detect Bluetooth Device.')

def wifiPrint(pkt):
	iPhone_OUI = '04:52:C7:0E:AD:3A'
	
	if pkt.haslayer(Dot11):
		# This is looking for layer 2 addresses
		wifiMAC = pkt.getlayer(Dot11).addr2

		if iPhone_OUI == wifiMAC[:8]:
			print('[*] Detected iPhone MAC: %s' % wifiMAC)
			btAddr = retBTaddr(wifiMAC)
			print('[+] Testing Bluetooth MAC: %s' % btAddr)
			checkBluetooth(btAddr)


for i in range(0, 5):
	scan()
	print("")
	time.sleep(5)

#conf.iface = 'enx384b76f00501'
#sniff(prn=wifiPrint)

# update: scan for signal strength and location


