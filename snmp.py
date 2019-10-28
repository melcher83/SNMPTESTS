from pysnmp.hlapi import *

def SNMP_V2MIB_GET(var,instance):

    iterator = getCmd(SnmpEngine(),
                  CommunityData('public'),
                  UdpTransportTarget(('192.168.127.52', 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', var, instance)))

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:  # SNMP engine errors
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                print(' = '.join([x.prettyPrint() for x in varBind]))

SNMP_V2MIB_GET('sysDescr',0)