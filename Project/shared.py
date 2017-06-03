
class CloseSnifferException(Exception):
    pass

class ReloadSniffer(Exception):
    pass

def get_direction(value):
    return "Master to Slave" if value else "Slave to Master"

def get_Address(addressIn, addrtype=":"): #pridobi naslov v hex glede na tip (shranjevanje na PCje z "_")
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