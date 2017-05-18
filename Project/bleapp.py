
import os
import sys
import io
import msvcrt
import datetime
import time
import glob  #najdi vec datotek
import matplotlib.pyplot as plt
from matplotlib import rcParams #figure autolayout
import pandas as pd
import argparse
import serial
import threading
import csv
import Queue
from SnifferAPI import Sniffer

mySniffer = None

uptime = {}
rcParams.update({'figure.autolayout': True})

def setup(serport, delay=3): #vzpostava povezava na COM port ki smo ga vnesli

    global mySniffer
    global uptime
    # inc. povezave na vnesena COM vrata
    print "Connecting to sniffer on " + serport
    mySniffer = Sniffer.Sniffer(serport)

    # Start sniffer
    mySniffer.start()
    if args.savedPackets == True:
        print "Saving all packets: ON"
    else:
        print "Saving all packets: OFF"
    # Pocakajmo na inicializacijo povezave
    time.sleep(delay)


def scanForDevices(scantime=5, stype = None): #iskanje aktivnih naprav deafault param je 5sec,

    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()

    return devs


def getAddress(addressIn, addrtype=":"): #pridobi naslov v hex glede na tip (shranjevanje na PCje z "_")
    addressIn = "%02X" % addressIn[0], "%02X" % addressIn[1], "%02X" % addressIn[2], "%02X" % addressIn[3], "%02X" % \
                addressIn[4], "%02X" % addressIn[5]
    addressList = list(addressIn)
    addressList.insert(1, addrtype)
    addressList.insert(3, addrtype)
    addressList.insert(5, addrtype)
    addressList.insert(7, addrtype)
    addressList.insert(9, addrtype)
    addressString = ''.join(addressList)
    return addressString

def getAddFromList(addr):
    i = str(addr)
    x = i.find("(")
    y = i.find(")")
    myString = i[(x+2):(y-1)]
    myString = myString.replace(",","")
    myString = myString.split()
    myString = myString[:len(myString)-1]

    for j in range(len(myString)): #spremeni elemente v int
        myString[j] = int(myString[j])

    myadd = getAddress(myString,"_")


    return myadd


def setMyList(devNum, listName, listAccAdd, listType, listRSSI):
    myList = [devNum, listName, listAccAdd, listType, listRSSI]
    return myList


def readFile(saveAddr):
    try:
        file_read = open(saveAddr+".csv")
        pktnum = sum(1 for row in file_read)-1  #preberemo stevilo vrstic
    except:
        pktnum = 0

    return pktnum

def writeFile(packetdata, saveAddr, pktnum = None):  # odpremo in pisemo glede na tip zahteve
    #glava vsebine

    header = ["Packet Number", "Time stamp", "Date and Time", "PDU Type", "RSSI", "Channel", "Direction", "Address Type",
                  "Header Length", "Payload Length", "PDU Length", "Header", "Payload", "Check CRC"]


    if saveAddr == "SensorTag/STvalues": #ce pisemo sensor tag vrednosti
        header = ["Entry Number", "Time stamp", "Date and Time", "Data Type", "Value"]
        pktnum = int(packetdata["Entry Number"])

    with open (saveAddr+".csv",'a') as allpckts:   #Shrani v CSV ce obstaja ali naredi ce ne
        writer = csv.DictWriter(allpckts, delimiter=',', lineterminator='\n', fieldnames=header)
        if pktnum<1:
            writer.writerow(dict((fn,fn) for fn in header))
            writer.writerow(packetdata)
        else:
            writer.writerow(packetdata)



def readStT(readUp, ms = None):#read string cas (0:00:00 format) oz (0:00:00.000000)
    if ms == None:
        min = int(readUp [-5:-3])
        hrs = int(readUp [:-6])
        sec = int(readUp [-2:])
        return sec, min, hrs
    else:
        ms = int(readUp [-6:])
        sec = int(readUp [-9:-7])
        min = int(readUp [-12:-10])
        hrs = int(readUp [:-13])
        return ms, sec, min, hrs


def getTime(seconds):
    minutes = 0
    hours = 0
    us = seconds % 1
    us = "{0:.6f}".format(us)
    us = str(us[2:])
    seconds = int(round(seconds))
    if (seconds >= 60):
        minutes = minutes + seconds / 60
        seconds = seconds % 60
    if (minutes >= 60):
        hours =  hours + minutes / 60
        minutes = minutes % 60


    if ((minutes < 10) and (seconds < 10)):
        timeformat = str(hours)+ ":" + "0" + str(minutes) + ":" + "0" +str(seconds)
    elif ((minutes < 10) and (seconds >= 10)):
        timeformat = str(hours)+ ":" + "0" + str(minutes) + ":" +  str(seconds)
    elif ((minutes >= 10) and (seconds < 10)):
        timeformat = str(hours)+ ":" + str(minutes) + ":" + "0" +str(seconds)
    elif ((minutes >= 10) and (seconds >= 10)):
        timeformat = str(hours)+ ":" + str(minutes) + ":" +  str(seconds)

    timeformat = timeformat+"."+us

    return timeformat




def setDict (devAddrs, address):
    number = len(address)
    address[devAddrs] = number+1



def getUptime (devAddrs, reset = None): #
    if reset is None:
        try:
            lastt = uptime [devAddrs][1]

        except:
            lastt = time.clock()
            mylist = [0, lastt]
            uptime [devAddrs] = mylist

        now = time.clock()
        delta = now-lastt
        return delta

    else:
        lastt = time.clock()
        uptime [devAddrs][1] = lastt


def getAverageRSSI(myDict, devAddr, type = None): #pridobimo povprecno vrednost Rssi od takrat ko smo natadnje klicali
# ali info ce type ni "get"

    vsota = float(sum(myDict[devAddr]))
    stevec = float(len(myDict[devAddr]))
    avgRssi = vsota / stevec
    avgRssi = "%.1f" % avgRssi
    if type == "get": #spraznimo seznam za nov prejem
        myDict[devAddr] = []

    return avgRssi


def getAddType(myAddType):
    myAddType = myAddType//64
    if myAddType == 0 or myAddType == False:
        myAddType = "Public"
    elif myAddType == 1 or myAddType == True:
        myAddType = "Random"
    else:
        myAddType = "Unknown"
    return myAddType


def getBlePacket():  # dobi stevilo prejetih BLE paketov

    packets = mySniffer.getPackets()

    for packet in packets:
        if packet.blePacket is not None:
            myPktBle = packet.blePacket

def getPacket():
    packets = mySniffer.getPackets()
    for packet in packets:
        print packet.timestamp


def checkAdvPackets():
    packets = mySniffer.getPackets(-1)
    advpackets = packets[-3:]

    for packet in advpackets:
        mySniffer.scan()
        packets = mySniffer.getPackets(-1)

        if packet.blePacket is not None:
            time.sleep(2)
            print "RSSI: {0}, Packet ID: {1}, Timestamp: {2}, Channel: {3}, Name:{4}, Length:{5}".format(d.RSSI,
                                                                                                       packet.id,
                                                                                                       packet.timestamp,
                                                                                                       packet.channel,
                                                                                                       packet.blePacket.name,
                                                                                                       packet.blePacket.length)
            print packet.payload


def readInput(caption, default, timeout = 5):

    class KeyboardThread(threading.Thread):
        def run(self):
            self.timedout = False
            self.input = ''
            while True:
                if msvcrt.kbhit():
                    chr = msvcrt.getche()
                    if ord(chr) == 13:
                        break
                    elif ord(chr) >= 32:
                        self.input += chr
                if len(self.input) == 0 and self.timedout:
                    break


    sys.stdout.write('%s(%s):'%(caption, default));
    result = default
    it = KeyboardThread()
    it.start()
    it.join(timeout)
    it.timedout = True
    if len(it.input) > 0:
        # wait for rest of input
        it.join()
        result = it.input
    print ''  # needed to move to next line
    return result



def selectDevice(devlist): #izberemo napravo za sledenje in povezavo
    count = 0
    global advflag

    if len(devlist):


        print "Found {0} BLE devices:\n".format(str(len(devlist)))

        mySniffer.getPackets(-1)

        for d in devlist.asList():
            """@type : Device"""
            count += 1

            atype = getAddType(d.txAdd)  #pridobimo tip in naslov naprav
            myAddrNow = getAddress(d.address)

            setMyListA = setMyList(count, d.name, myAddrNow, atype, d.RSSI)
            print "Nu.:{0}, name:{1}, Address:{2}, Type:{3}, RSSI:{4}".format(setMyListA[0], setMyListA[1],
                                                                                         setMyListA[2], setMyListA[3],
                                                                                      setMyListA[4])
          # prepoznaj komando

        fchar = None
        print "[dev num] + [G, C, C T] (graphs, CONN, CONN + Display data)"
        i = readInput("Enter command:\n ", "0")
        try:
            if ((int(i[0]) in range(1, 11)) and (i[-1] == i[0])):
                i = int(i)

            elif ((int(i[0]) in range(1, 11) and type(i[2]) is str)):
                fchar = i[2:]
                i = int(i[0])

            if ((i > 0) and  (i <= count)):
                advflag = 1
                return (devlist.find(i - 1), fchar)
            else:
                if (i[0]  == 'q'):
                    fchar = 'q'
                else:
                    fchar = 0
                return (0, fchar)

        except:
            return (0, i)


def getSf(sf, mode = False):
    sf = str(sf)
    com = ["D", "H", "T", "S", "L", "U"]
    out = ["d", "h", "m", "s", "ms", "us"]
    j = 0
    list =  com
    repl = out
    while 1:
        if mode == True:
            if "ms" in sf:
                sf = sf.replace("ms", "L")
                break
            elif "us" in sf:
                sf = sf.replace("us", "U")
                break
            else:

                list = out
                repl = com

        for i in list:
            if i in sf:
                sf = sf.replace(i, repl[j])
                break
            j +=1
        break
    if mode == False and "m" in sf and "ms" not in sf:
        sf = sf.replace("m", "min")

    return sf


def getCol(i):
    colors=["#5a5c51", "#daad86", "#312c32", "#a52a2a", "#708090"]
    return colors[i]

def setTicks(grph):
    ticks = grph.xaxis.get_ticklocs() #stevilo oznak
    if len(ticks) > 12:
        n = len(ticks)/12
    else:
        n = 1
    ticklabels = [l.get_text() for l in grph.xaxis.get_ticklabels()]
    grph.xaxis.set_ticks(ticks[::n])
    grph.xaxis.set_ticklabels(ticklabels[::n])
    plt.gcf().autofmt_xdate() # trenutn graf -> rotacija casovnega formata


def showGraph(saveAddr, type , st, et, sf = 'T'):
    plt.close()

    if type != "devs":
        
        filename = (saveAddr+".csv")
        df = pd.read_csv(filename, parse_dates=[2])
        timerange = (df['Date and Time'] > st) & (df['Date and Time'] <= et) #casovni okvir
        df = df.loc[timerange] #poberi podatke samo v dolocenem casovnem okviru

    if type == "freq": # koliko paketov v dolocenem casu
        df = df.set_index('Date and Time').resample(sf, how = "count")
        grph = df.plot(legend = False, kind = "bar", y = "Packet Number", width=1, color="#5a5c51")
        setTicks(grph)
        plt.ylabel('Paket/'+getSf(sf))
        plt.xlabel("Datum in cas")

    if type == "rot":
        df = df.set_index('Date and Time').resample(sf, how = "mean")
        grph = df.plot(legend = False, style='o', y = "RSSI")
        setTicks(grph)
        plt.ylabel('Avg RSSI/'+getSf(sf))
        plt.xlabel("Datum in cas")

    elif type == "ch":
        df["Channel"].plot(kind ="hist", bins = range(min(df["Channel"]), max(df["Channel"])+2, 1), alpha = 0.8, color = getCol(4))
        plt.xlabel('Stevilka kanala')
        plt.ylabel('Stevilo paketov')

    elif type == "rssi": # koliko paketov od dolocenega RSSIja
        df['RSSI'].plot(kind = "hist", alpha= 0.7,
                        bins = range(min(df["RSSI"]), max(df["RSSI"])+1, 1), color = "#312c32") #nastavimo x interval na 1
        plt.xlabel('Sprejeta moc [dBm]')
        plt.ylabel('Stevilo paketov')

    elif type == "devs":
        allFiles = glob.glob("*.csv")
        d = [] #seznam DFjev

        for file in allFiles: #naredi df za vsak CSV
            try:
                c = pd.read_csv(file,parse_dates=[2])

                timerange = (c['Date and Time'] > st) & (c['Date and Time'] <= et)
                c = c.loc[timerange]
                d.append (c.set_index('Date and Time').resample(sf, how = "count"))
            except:
                pass

        fig = plt.figure()
        ax = fig.add_subplot(111)
        axx = plt.subplot() #naredi axes




        df = pd.concat(d, keys=allFiles) #zdruzimo "tabeli" in dodamo kljuce
        for i in range(0,len(allFiles)):
            df.ix[allFiles[i]].plot(stacked = True, ax =ax, kind = "bar", y="Packet Number", color = getCol(i),
                                                width =1, position = 0, label = str(allFiles[i]).replace(".csv", ""), sharex =True)



        ticks = axx.xaxis.get_ticklocs() #stevilo oznak
        if len(ticks) > 12:
            n = len(ticks)/12
        else:
            n = 1
        ticklabels = [l.get_text() for l in axx.xaxis.get_ticklabels()]
        axx.xaxis.set_ticks(ticks[::n])
        axx.xaxis.set_ticklabels(ticklabels[::n])
        plt.gcf().autofmt_xdate() # trenutn graf -> rotacija casovnega formata
        plt.ylabel('Paket/'+getSf(sf))
        plt.xlabel("Datum in cas")


    if type != "devs":
        plt.suptitle(saveAddr)


    plt.savefig("Grafi/"+saveAddr+str(datetime.datetime.now().strftime("_%Y_%m_%d_%H_%M"))+".png")
    plt.show()


def getHumTemp(v): #preberemo vlago in temp naprava SensorTag
        vMSB = v[1]
        vLSB = v[0]
        temp = float(vMSB*256+vLSB)
        tempA = (temp/65536)*165-40
        tempA = round(tempA,2)
        print "Tamb: %.1f C" % tempA

        hMSB = v[3]
        hLSB = v[2]
        hum = float(hMSB*256+hLSB)
        humA = (hum/65536.0*100)
        print "Hum: %.1f %%" % humA
        return humA, tempA

def getLux(v):
    vMSB = v[1]
    vLSB = v[0]
    vMSB = "{0:08b}".format(vMSB)
    E = int(vMSB[0:4],2) #prvi MSB 4 biti nakazujejo eksponentni znacaj
    E = 0.01*(2**E)
    R = vLSB+(int(vMSB[4:],2))<<4 ##shift v levo za 4 bite
    lux = round(E*R, 2)
    print "E: "+str(lux)+ " lx"
    return lux

def getUs(startT):
    tus = int(((time.clock()-startT)%1)*1000000)
    if len(str(tus)) != 6:
        digits = len(str(tus))
        for mzero in range(0,(6-digits)):
            tus = "0"+str(tus)

    return tus

def clkSin():
    lastt = datetime.datetime.now() #sinhronizacija datetime.now in time.clock()
    slpt = "0."+str(lastt.microsecond)
    slpt = 1 - float(slpt)
    time.sleep(slpt)
    starT = time.clock()
    return starT




queue = Queue.Queue()

class savePrcPkt (threading.Thread): #shranjevanje obdelanih paketov
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue


    def run(self):

        plist = self.queue.get()

        packet = plist[0]
        absT = plist[2]
        relT = plist[3]
        pcktnum = plist[1]
        saveAddr = plist[4]


        myBle = packet.blePacket
        packet_data = {"Packet Number": pcktnum, "Time stamp": relT, "Date and Time": absT, "PDU Type": packet.eventCounter, #PDU Type je eventCounter
                                        "RSSI": str(packet.RSSI), "Channel":packet.channel, "Direction":getDirect(packet.direction), "Address Type": "Random",
                                        "Header Length":packet.headerLength,  "Payload Length":packet.payloadLength, "PDU Length":myBle.length,
                                        "Header":packet.packetList[:6], "Payload":packet.payload, "Check CRC":getCrcCheck(packet.crcOK)}

        writeFile(packet_data, saveAddr, pcktnum)
        self.queue.task_done()







def saveAll():# Shranujemo vse pakete

    starT = clkSin() #zacetni time sinhroniziran z datetime


    while 1:
        if advflag == 1:
            savDList = scanForDevices(4, 1) #2 na vsaki sekundi zakasnitev ####NASTAVLJAMO######
        try:
            packets = mySniffer.getPackets(-1)

            for packet in packets:

                myBle = packet.blePacket

                if myBle is not None:

                    if advflag == 1: #smo v ADV nacinu
                        dAddr = getAddress(myBle.advAddress[0:len(myBle.advAddress)-1])
                        saveAddr = dAddr.replace(":","_")

                        for devs in savDList.asList():
                            devn = getAddress(devs.address)
                            if devn == dAddr: #pakete samo od dolocene nap.*****
                                pktnum = readFile(saveAddr) #preberemo st vrstic
                                microsec = getUs(starT)
                                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S."+str(microsec)) #datetime.datetime do 1s + time.clock() na us

                                packet_data = ({"Packet Number": pktnum, "Time stamp": getTime(getUptime(dAddr,None)), "Date and Time": now, "PDU Type": getPduType(myBle.advType), #naredimo slovar
                                        "RSSI": str(packet.RSSI), "Channel":packet.channel, "Direction":getDirect(packet.direction), "Address Type": getAddType(devs.txAdd),
                                        "Header Length":packet.headerLength,  "Payload Length":packet.payloadLength, "PDU Length":myBle.length,
                                        "Header":packet.packetList[:6], "Payload":packet.payload, "Check CRC":getCrcCheck(packet.crcOK)})

                                writeFile(packet_data, saveAddr, pktnum) #Shrani ADV podatke v CSV

                    elif advflag == 0: #smo v follow/CONN nacinu

                        microsec = getUs(starT)
                        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S."+str(microsec)) #datetime.datetime do 1s + time.clock() na us
                        dAddr = getAddress(myBle.advAddress[0:len(myBle.advAddress)-1])
                        pktnum = readFile(saveAddr) #preberemo st vrstic
                        packet_data = {"Packet Number": pktnum, "Time stamp": getTime(getUptime(dAddr,None)), "Date and Time": now, "PDU Type": packet.eventCounter, #PDU Type je eventCounter
                                        "RSSI": str(packet.RSSI), "Channel":packet.channel, "Direction":getDirect(packet.direction), "Address Type": getAddType(devs.txAdd),
                                        "Header Length":packet.headerLength,  "Payload Length":packet.payloadLength, "PDU Length":myBle.length,
                                        "Header":packet.packetList[:6], "Payload":packet.payload, "Check CRC":getCrcCheck(packet.crcOK)}


                        writeFile(packet_data, saveAddr, pktnum) #Shrani podatke v CSV
                    pktnum +=1

        except:
            pass

        if advflag == 2:  #conn + obdelava
            break







def exceptErr(): #ko zaklucimp program ali napaka
    mySniffer.doExit()
    time.sleep(0.2)
    sys.exit(-1)

def getPduType(value):
    value = value % 16      #Snifer knjiznica nima ustrezno defniranega advType
    if value == 0:
        type = "ADV_IND"
    elif value == 1:
        type = "ADV_DIRECT_IND"
    elif value == 2:
        type = "ADV_NONCONN_IND"
    elif value == 3:
        type = "ADV_SCAN_REQ"
    elif value == 4:
        type = "ADV_SCAN_RSP"
    elif value == 5:
        type = "CONNECT_REQ"
    elif value == 6:
        type = "ADV_SCAN_IND"
    return type

def getDirect(value):
    if value == True:
        dir = "Master to Slave"
    else:
        dir = "Slave to Master"
    return dir

def getCrcCheck(value):
     if value == True:
         crc = "OK"
     else:
         crc = "NOK"
     return crc


def readTval(inp): #preberi vnos za start in end time
    if "us" in inp:
        value = int(inp.replace("us", ""))
        d = datetime.timedelta(microseconds = value)
    elif "ms" in inp:
        value = int(inp.replace("ms", ""))
        d = datetime.timedelta(miliseconds = value)
    elif "s" in inp:
        value = int(inp.replace("s", ""))
        d = datetime.timedelta(seconds = value)
    elif "m" in inp:
        value = int(inp.replace("m", ""))
        d = datetime.timedelta(minutes = value)
    elif "h" in inp:
        value = int(inp.replace("h", ""))
        d = datetime.timedelta(hours = value)
    elif "d" in inp:
        value = int(inp.replace("d", ""))
        d = datetime.timedelta(days = value)
    else:
        d = inp
    return d

def graphUI(devName):
    devName = getAddress(devName.address, "_")

    while 1:
        typ = raw_input("Enter type(devs, freq, rssi, ch, rot) or b for back:")

        if typ == "b":
            break
        stT = raw_input("Enter start time relative to now (use - and us, ms, s, m, h, d) or fixed YYYY-MM-DD  hh:mm:ss.xxxxxx: ")
        stpT = raw_input("Enter stop time relative to start time (use + and us, ms, s, m, h, d) or fixed YYYY-MM-DD  hh:mm:ss.xxxxxx: ")
        if typ == "devs" or typ == "freq" or typ == "rot":
            intr = raw_input("Enter interval (us, ms, s, m, h, d): ")
            intr = getSf(intr, True)
            if len(intr) == 0:
                intr = "T" #privzeti interval minute
        else:
            intr = None

        if stT.count('-')==1:
            delta = readTval(stT)
            stT = datetime.datetime.now()+delta
        if "+" in stpT :
            delta = readTval(stpT)
            stpT = str(stT+delta)
            stT = str(stT)


        if len(stT) == 0:
            stT = "2015-08-20"
        if len(stpT) == 0:
            stpT = str(datetime.datetime.now())
        if len(typ) == 0:
            typ =  "freq"

        print "Time frame: "+stT+" - "+stpT

        showGraph (devName, typ, stT, stpT, intr)



out_queue = Queue.Queue()




if __name__ == '__main__':

    #Glavni program

    # Instantiate the command line argument parser
    argparser = argparse.ArgumentParser(description="Interacts with the Bluefruit LE Friend Sniffer firmware")


    argparser.add_argument("serialport", #obevnzi armunt
                           help="serial port location ")   #podamo stevlko serijskih vrat

    # opcijski argument:

    argparser.add_argument("-sa", "--savedPackets",
                           dest="savedPackets",
                           action="store_true",
                           default=False,
                           help="Saving all packets in txt file.")

    # Parser the arguments passed in from the command-line
    args = argparser.parse_args()

    # Display the libpcap logfile location



    # Poiskusimo odpreti serijska vrata
    try:
        setup(args.serialport)
    except OSError:
        # applikacije vrne error ce smo napisali napacena COM vrata
        print "Unable to open serial port '" + args.serialport + "'"
        sys.exit(-1)

    try: #glavni program

        myLastDevlist = []
        d = None
        myDevlist = []


        if (args.savedPackets == True):#zazenemo nit za shranjevanje
            advflag = 1
            saving = threading.Thread(target=saveAll)
            saving.daemon = True  # oznacimo kot daemon, to pomeni da ko se program zakluci, koncamo tudi shranjevanje
            saving.start()      #deluje v ozadju

        d =  0
        while 1:
            while d == 0: # Isci naprave dokler ne izberemo
                
                devlist = scanForDevices()
                lenDev = len(devlist)
                if lenDev:
                    d, cchr = selectDevice(devlist)
                    if cchr == 'q':
                        break
    

            if ((d is not 0) and (cchr[0] == "C")):
                while mySniffer.inConnection == False:
                    starT = clkSin() #zacetni time sinhroniziran z datetime
                    saveAddr = getAddFromList(d)

                    i = 0
                    mySniffer.follow(d)
                    advflag = 0
                    if msvcrt.kbhit():
                        if (msvcrt.getch() == "b"):
                            break
                        elif (msvcrt.getch() == "q"):
                                cchr = 'q'
                                break
                if mySniffer.inConnection == True:
                    advflag = 2 #prekinemo saving thread
                    saving.join()
                    pktnum = readFile(saveAddr)
                    entnum = readFile("SensorTag/STvalues")

                    while 1:

                        if  "T" not in cchr:
                            break
                        elif "T"  in cchr:
                            packets = mySniffer.getPackets()
                            dAddr = saveAddr.replace("_",":")


                            for  packet in packets:
                                myBle = packet.blePacket
                                if myBle is not None:
                                    dt = savePrcPkt(out_queue)
                                    dt.daemon = False
                                    dt.start()
                                    #datetime.datetime do 1s + time.clock() na us
                                    relT = getTime(getUptime(dAddr,None))
                                    microsec = getUs(starT)
                                    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S."+str(microsec))
                                    x = [packet, pktnum, now, relT, saveAddr]
                                    out_queue.put(x) #daj v cakalno vrsto

                                    pktnum += 1

                                    if packet.payload[22:24] == [41, 0]: #handle za temp
                                        i +=1
                                        mydata = packet.payload[24:28] #4B
                                        if i > 1:
                                            hum, temp =getHumTemp(mydata)
                                            data = {"Entry Number":entnum, "Time stamp":relT, "Date and Time":now, "Data Type":"TEMP",  "Value":temp}
                                            writeFile(data, "SensorTag/STvalues")
                                            entnum +=1
                                            data = {"Entry Number":entnum, "Time stamp":relT, "Date and Time":now, "Data Type":"HUM",  "Value":hum}
                                            writeFile(data, "SensorTag/STvalues")
                                            entnum +=1


                                    elif packet.payload[22:24] == [65, 0]: #handle za opt oz 0x41
                                        mydata = packet.payload[24:26] #2B
                                        lux = getLux(mydata)
                                        data = {"Entry Number":entnum, "Time stamp":relT, "Date and Time":now, "Data Type":"LUX",  "Value":lux}
                                        writeFile(data, "SensorTag/STvalues")
                                        entnum +=1

                            out_queue.join() #pocakaj da so vsi

                        if msvcrt.kbhit():
                        # The user entered a key. Check to see if it was a "c".
                            if (msvcrt.getch() == "b"):
                                if (args.savedPackets == True):#zazenemo nit za shranjevanje
                                    advflag = 1
                                    saving = threading.Thread(target=saveAll)
                                    saving.daemon = True  # oznacimo kot daemon, to pomeni da ko se program zakluci, koncamo tudi shranjevanje
                                    saving.start()      #deluje v ozadju
                                break
                            elif (msvcrt.getch() == "q"):
                                cchr = 'q'
                                break

            elif (d != 0) and ("G" in cchr):
                grph = graphUI(d)

            elif d is not 0 and cchr  == "A":
                mySniffer.follow(d)

            elif cchr == 'q':
                break

            d, cchr = selectDevice(devlist)






        print "Program Exit"

        # Close gracefully
        mySniffer.doExit()
        sys.exit()

    except KeyboardInterrupt:
        exceptErr()
