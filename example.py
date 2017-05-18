import time
from SnifferAPI import Sniffer
from SnifferAPI import Devices

nPackets = 0
mySniffer = None




def setup():
    global mySniffer
    
    # Initialize the sniffer on COM port COM19.
    # mySniffer = Sniffer.Sniffer("COM19")
    # Or initialize and let the sniffer discover the hardware.
    mySniffer = Sniffer.Sniffer()
    # Start the sniffer module. This call is mandatory.
    mySniffer.start()

    # Wait to allow the sniffer to discover device mySniffer.
    time.sleep(5)
    # Retrieve list of discovered devicemySniffer.
    d = mySniffer.getDevices()
    # Find device with name "Example".
	
    dev = d.find('')
	
    
    if dev is not None:
		print "Device found"
		print "dev",dev
        # Follow (sniff) device "Example". This call sends a REQ_FOLLOW command over UART.
		mySniffer.follow(dev)
    else:
        print "Could not find device"
		

	
	

	
	
	
def loop():
    # Enter main loop
	
    nLoops = 0
    while True:
        time.sleep(0.2)
        # Get (pop) unprocessed BLE packets.
        packets = mySniffer.getPackets()
        enc=Packet.encrypted()
        processPackets(packets) # function defined below
        
        nLoops += 1
        
        # print diagnostics every so often
        if nLoops % 20 == 0:
            print mySniffer.getDevices()
            print "inConnection", mySniffer.inConnection
            print "currentConnectRequest", mySniffer.currentConnectRequest
            print "packetsInLastConnection", mySniffer.packetsInLastConnection
            print "nPackets", nPackets
			print "packet encryptio" ,  enc
		
        
# Takes list of packets
def processPackets(packets):
    for packet in packets:
        # packet is of type Packet
        # packet.blePacket is of type BlePacket
        global nPackets
        # if packet.OK:
        # Counts number of packets which are not malformed.
        nPackets += 1
    
setup()

loop()
