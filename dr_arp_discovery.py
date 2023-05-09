#This code is based on https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/
import sys
import os
import timeit
import time
import datetime
import requests

from scapy.all import srp, Ether, ARP, conf


if __name__ == "__main__":

    try:
        interface = input("Enter desired interface: ")
        ips = input("Enter range of IPs to Scan for: ")

    except KeyboardInterrupt:
        print ("\n User requested shutdown")
        print ("Quiting...")
        sys.exit(1)


corrida = 15
empresa = []


for i in range(0,3):
        print ("\n Scanning... ")
        start_time = timeit.default_timer()
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout=corrida, iface=interface, verbose=False)


        timeStamp = time.time()
        strTimeStamp = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y.%m.%d.%H.%M.%S')
        salida = open("T_"+interface+"_"+strTimeStamp+".txt",'w')
        salida.write(ips + "\n")
        salida.write("MAC_Adress"+"\t"+"IP"+"\n")


        link = ("https://api.macvendors.com/")

        #print ans.summary()
        print ('MAC - IP')
        for s, r in ans:
            print (r.sprintf(r'%Ether.hwsrc% - %ARP.psrc%'))
            salida.write(r.sprintf(r'%Ether.hwsrc% - %ARP.psrc%')+"\n")
            x = r.sprintf(r'%Ether.hwsrc%')

            if x  not in empresa:
              empresa.append(x)




        stop_time = timeit.default_timer()
        total_time = stop_time - start_time


        print ("\n Scan Complete!")
        print ("Scan Duration: %s" %(total_time))

        corrida = corrida*2

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white
M = '\033[34m'  # morado

promedio = {}

notfound = 0;

#print(empresa)

t = int(len(empresa))

print(str(t))

for i in empresa:
        result = requests.get(link + i)
        if "errors" not in result.text:
            owner = result.text

            # print(M + "\nMAC Address found!\n")
            # print( G + "ADDRESS " + W + "|" + C + " OWNER ")
            # print( G + i.upper() +  W + "  | " + C + owner)

            if owner not in promedio:
                promedio.setdefault(owner, 1)
            else:
                x = promedio.pop(owner)
                x = x + 1
                promedio.setdefault(owner, x)
        else:
            print(R + "\nMAC Address not found.")
            notfound = notfound + 1

        time.sleep(2)


#print(promedio)

total = float(len(empresa))

Frecuencia = open("Frecuencia_"+interface+".txt",'w')
for key in promedio:

 temp = float(promedio[key])
 temp2 = float( (temp/total) * 100.0)
 temp3 = float( (notfound/total)*100.0)

 Frecuencia.write(key + " " +str(temp2)+ "\n" )

Frecuencia.write("No encontradas " + str(temp3) +"\n")


#print(repetidos)



