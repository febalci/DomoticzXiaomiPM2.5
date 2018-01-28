#!/usr/bin/env python
#v.1.0.0
import Domoticz
import socket
import hashlib
import pyaes
import struct


class xiaomiaqi:

    infopackage_pre = '{"id":'
    infopackage_end = ',"method":"get_prop","params":["power","usb_state","aqi","battery"]}'
    infopackage_all = None
    m_counter = 1
    token = None
    m_key = None
    m_iv = None
 
    hellopackage = b'\x21\x31\x00\x20\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    magicnumber = b'\x21\x31'
    unknown1 = b'\x00\x00\x00\x00'
    deviceid = None
    stamp = None
    packagelength = 0
    header = None
    headertemp = None

    def __init__(self, host=None, port=None): #54321
        self.host = host
        self.port = int(port)
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            Domoticz.Log('Socket Error!')      
        return

    def request_hello(self):

        try:
            #Set the whole string
            self.s.sendto(self.hellopackage, (self.host, self.port))
         
            # receive data from client (data, addr)
            d = self.s.recvfrom(1024)
            reply = d[0]
            addr = d[1]
         
            Domoticz.Debug ('Server reply : ' + str(reply))
            self.token = reply[16:32]
            self.deviceid = reply [8:12]
            self.stamp = reply [12:16]
            Domoticz.Debug ('Stamp='+str(self.stamp))
            Domoticz.Debug('Token='+str(self.token))
            self.m_key = self.md5(self.token)
            Domoticz.Debug('Key='+str(self.m_key))
            self.m_iv = self.md5(self.m_key+self.token)
            Domoticz.Debug('iv='+str(self.m_iv))
     
        except socket.error as msg:
            Domoticz.Debug ('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        return
        
    def request_info(self):
        try:
            self.infopackage_all = self.infopackage_pre + str(self.m_counter) + self.infopackage_end
            Domoticz.Debug ('Infopackage= '+self.infopackage_all)
            encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.m_key, self.m_iv))

            encrypted = encrypter.feed(self.infopackage_all)
            encrypted += encrypter.feed()

            Domoticz.Debug ('Encrypted='+str(encrypted))

            # Add package header
            self.packagelength = len(encrypted)+32
            Domoticz.Debug ('Package Length = '+str(self.packagelength))
    
            self.header = self.magicnumber
            self.header += struct.pack ('>h',self.packagelength)
            self.header += self.unknown1
            self.header += self.deviceid #Device ID
            self.header += self.stamp
            self.headertemp = self.header
            self.headertemp += self.token
            self.headertemp += encrypted
            self.header += self.md5(self.headertemp)
            self.header += encrypted
            Domoticz.Debug ('Header= '+str(self.header))
    
            self.s.sendto(self.header, (self.host, self.port))

            # receive data from client (data, addr)
            d = self.s.recvfrom(1024)
            reply = d[0]
            addr = d[1]

            decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(self.m_key, self.m_iv))
            decrypted = decrypter.feed(reply[32:])
            # Again, make a final call to flush any remaining bytes and strip padding
            decrypted += decrypter.feed()

            Domoticz.Debug  ('Response= '+str(decrypted))

        except socket.error as msg:
            Domoticz.Debug ('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])

        return decrypted.decode('utf-8')

    def md5(self,data: bytes) -> bytes:
        # Calculates a md5 hashsum for the given bytes object.
        checksum = hashlib.md5()
        checksum.update(data)
        return checksum.digest()
