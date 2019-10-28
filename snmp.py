from pysnmp.hlapi import *

def SNMP_V2MIB_GET(HOST, COMMUNITY, VAR, INSTANCE):

    iterator = getCmd(SnmpEngine(),
                      CommunityData(COMMUNITY),
                      UdpTransportTarget((HOST, 161)),
                      ContextData(),
                      ObjectType(ObjectIdentity('SNMPv2-MIB', VAR, INSTANCE)))

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                return [x.prettyPrint() for x in varBind]

class SNMP_OBJECT:
    def __init__(self,HOST,COMMUNITY):
        self.HOST=HOST
        self.COMMUNITY=COMMUNITY
        self.sysDescr=SNMP_V2MIB_GET(self.HOST,self.COMMUNITY,'sysDescr',0)
    def GET_DESC(self):
        return self.sysDescr[1]

SWITCH1=SNMP_OBJECT('192.168.127.52','public')
print(SWITCH1.GET_DESC())
