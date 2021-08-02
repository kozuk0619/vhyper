#John Rawley and Logan Anderson
import tkinter as tk
from tkinter import filedialog
import threading
import dpkt
import socket

#########################################################################



def scanPcap(pcap, outfile, infile, options):
    source_ips = [] #unique source IP address in the Pcap 
    poss_bots= [] #count of occurences of the tcp packet pattern
    tcp_count = []
    syn_count = []
    ack_count = []
    udp_count = []
    udp_pairs = []
    udpplain_count = []
    udpplain_ports = []
    vse_count = []
    greip_count = []
    greeth_count = []
    dns_count = []
    i = 0
    i_tcp = 0
    last_four_tcp = []
    # old_sip = ""
    # old_dip = ""
    # old_sport=""
    # old_dport=""
    is_tcp = True
    is_udp = False
    for (ts,buf) in pcap:
        i +=1
        if i % 10000 == 0:
            print(i)
            #if i > 50000:
            #	break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            #print(eth.src)
            # read the source IP in src
            src = socket.inet_ntoa(ip.src)
            if str(src) not in source_ips:
                source_ips.append(str(src))
                poss_bots.append(0)
                tcp_count.append(0)
                syn_count.append(0)
                ack_count.append(0)
                udp_count.append(0)
                udp_pairs.append((0,0))
                vse_count.append(0)
                greip_count.append(0)
                greeth_count.append(0)
                dns_count.append(0)
                udpplain_count.append(0)
                udpplain_ports.append(0)
            if ip.p==dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                is_tcp = False
                is_udp = True
            elif ip.p==dpkt.ip.IP_PROTO_TCP:
                i_tcp += 1
                tcp = ip.data
                is_tcp = True
                last_four_tcp.append((tcp.flags, src, socket.inet_ntoa(ip.dst)))
                if len(last_four_tcp) > 4:
                    last_four_tcp.pop(0)
            else:
                pass
            index = 0
            for item in source_ips:
                if item == str(src):
                    break
                else:
                    index += 1
            if( is_tcp and (tcp.dport == 23 or tcp.dport == 2323)):
                tcp_count[index] += 1
                if(tcp.dport == 2323):
                    if tcp_count[index] % 10 == 0:
                        poss_bots[index] += 10
            if options[0].get() == 1: # ACK FLOOD
                #Pattern two flags = 16 from ip1, then two 4 from dest of ip1
                if(is_tcp):
                    tmp_tcp, tmp_src, tmp_dst = last_four_tcp[0]
                    if last_four_tcp[1] == (16, tmp_src, tmp_dst):
                        if last_four_tcp[2] == (4, tmp_dst, tmp_src):
                            if last_four_tcp[3] == (4, tmp_dst, tmp_src):
                                temp_index = 0
                                for j in source_ips:
                                    if str(tmp_src) == j:
                                        break
                                    else:
                                        temp_index +=1
                                ack_count[temp_index] += 4
            if options[1].get() == 1: # DNS FLOOD
                if is_udp:
                    if udp.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            if dns.op == dpkt.dns.DNS_QUERY:
                                dns_count[index] += 1
                        except Exception as e:
                            #pass
                            print(e)
            if options[2].get() == 1: # SYN FLOOD
                #CHecking length of packet = 74 and syn ==1 ack == 0
                #
                #	print("NOT TCP")
                #	continue
                if(is_tcp):
                    if ((tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)):
                        if(ip.len == 60):
                            syn_count[index] += 1
            if options[3].get() == 1: # GRE-IP FLOOD
                if ip.p == dpkt.ip.IP_PROTO_GRE:
                    gre = ip.data
                    ip2 = gre.data
                    if  isinstance(ip2, dpkt.ip.IP):
                        src2 = socket.inet_ntoa(ip2.src)
                        if str(src) != str(src2):
                            greip_count[index] += 1 
            if options[4].get() == 1: # GRE-ETH FLOOD
                if ip.p == dpkt.ip.IP_PROTO_GRE:
                    gre = ip.data
                    if gre.p == 25944:
                        eth2 = gre.data
                        if eth2.type == 2048:
                            ip2 = eth2.data
                            src2 = socket.inet_ntoa(ip2.src)
                            if str(src) != str(src2):
                                greeth_count[index] += 1
            if options[5].get() == 1: # VSE FLOOD
                if not is_tcp:
                    if(udp.ulen == 33 and udp.dport == 27015):
                            vse_count[index] += 1
            if options[6].get() == 1: # HTTP FLOOD
                pass
            if options[7].get() == 1: # UDPplain FLOOD
                if is_udp:
                    if ip.tos == 0 and ip.ttl == 64 and ip.offset == 0 and udp.ulen == 520:
                        if udpplain_ports[index] == udp.dport:
                            udpplain_count[index] += 1
                        else:
                            udpplain_ports[index] = udp.dport
            if options[8].get() == 1: # UDP FLOOD
                if is_udp:
                    if(udp.ulen == 520):
                        temp_oldport, temp_port = udp_pairs[index]
                        if temp_oldport != temp_port and temp_port == udp.dport:
                            udp_count[index] += 2
                        udp_pairs[index] = (temp_port, udp.dport)
        except Exception as e:
            print(e)
            pass
    mutex.acquire()
    out = open(outfile, 'a')
    source_ips = list(source_ips)
    out.write(infile + "\n")
    top_line = '{:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {}'.format("IP",
                                                                                                                                    "Scanning",
                                                                                                                                    "ACK Flood",
                                                                                                                                    "DNS Flood",
                                                                                                                                    "SYN Flood",
                                                                                                                                    "GRE-IP Flood",
                                                                                                                                    "GRE-ETH Flood",
                                                                                                                                    "VSE Flood",
                                                                                                                                    "HTTP Flood",
                                                                                                                                    "UDPplain Flood",
                                                                                                                                    "UDP Flood", "\n")
    out.write(top_line)
    for item in range(0, len(source_ips)):
        out_line = '{:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {}'.format(source_ips[item],
                                                                                                                    str(poss_bots[item]),
                                                                                                                    str(ack_count[item]),
                                                                                                                    str(dns_count[item]),
                                                                                                                    str(syn_count[item]),
                                                                                                                    str(greip_count[item]),
                                                                                                                    str(greeth_count[item]),
                                                                                                                    str(vse_count[item]),
                                                                                                                    "0",
                                                                                                                    str(udpplain_count[item]),
                                                                                                                    str(udp_count[item]), "\n")
        out.write(out_line)
    out.close()
    mutex.release()
    print("done")
def analyzeCap(infile, outfile, options, window):
    # Open pcap file for reading
    #f = open('Capture_4/infected1-02', 'rb')
    #pass the file argument to the pcap.Reader function
    newwindow = tk.Toplevel(window)
    newlabel = tk.Label(newwindow, text="Analyzing...", height=2, width=80)
    newlabel.pack()
    newtext = tk.Text(newwindow, height=4, width=80, background="white")
    newtext.pack()
    f = open(infile,'rb')
    pcap = dpkt.pcap.Reader(f)
    scanPcap(pcap, outfile, infile, options)
    newtext.insert("end", infile + " is done!\n")
    f.close()

#########################################################################

# Function for opening the
# file explorer window
def browseFiles(file_select):
    files = filedialog.askopenfilenames(initialdir = "/", title = "Select a File", 
                                                    filetypes = ( ("all files", "**"), ("PCAP files", "*.pcap*"), ("Text files", "*.txt*")))
    files_analyze = list(files)
    #clearFiles(file_select)

    for x in files_analyze:
        file_select.insert("end", x + '\n')
      
def clearFiles(file_select):
    file_select.delete(1.0,"end")

def check_all(flood_var):
    for item in flood_var:
        item.set(1)

def uncheck_all(flood_var):
    for item in flood_var:
        item.set(0)

def analyzeFiles(flood_var, file_select, file_select2, window):
    result = (file_select.get("1.0","end")).strip('\n')
    files = result.split('\n')
    if len(files) > 5:
        files = files[:5]

    result = (file_select2.get("1.0","end")).strip('\n')
    files2 = result.split('\n')
    threads = []

    for i in range(0,len(files)):
        threads.append(threading.Thread(target=analyzeCap, args=(files[i], files2[0], flood_var, window,)))
    for i in range(0,len(threads)):
        threads[i].start()

# lock
mutex = threading.Lock()

def main():
    # vars
    check_arr = []

    # setup the GUI
    window = tk.Tk()
    window.title('VHYPER')
    window.geometry("585x500")
    window.config(background = "white")

    flood_var = [tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar()]

    # labels
    label_file_explorer = tk.Label(window, text = "Welcome to the VHYPER GUI!", width = 73, height = 2, fg = "blue")
    select_label = tk.Label(window, borderwidth=1, relief="solid", height = 9, width = 100, background = "white")
    analysis_label = tk.Label(window, borderwidth=1, relief="solid", height = 9, width = 100, background = "white")
    end_label = tk.Label(window, borderwidth=1, relief="solid", height = 9, width = 50, background = "white")
    output_label = tk.Label(window, borderwidth=1, relief="solid", height = 6, width = 100, background = "white")
    browse_label = tk.Label(window, text = "Select files to scan: (max 5)", width = 30, height = 2)
    choose_label = tk.Label(window, text = "Select additional analysis options:", width = 30, height = 2)
    return_label = tk.Label(window, text = "Select file to send output:", width = 30, height = 2)
    
    
    # text
    file_select = tk.Text(window, height = 5, width = 70)
    file_select2 = tk.Text(window, height = 2, width = 70)
    
    # buttons
    button_explore = tk.Button(window, text = "Browse Files", command=lambda:browseFiles(file_select))
    button_clear = tk.Button(window, text = "Clear Files", command=lambda:clearFiles(file_select))
    button_exit = tk.Button(window, text = "Exit", width = 10, command = exit)
    button_analyze = tk.Button(window, text = "Analyze Selected Files", command=lambda:analyzeFiles(flood_var, file_select, file_select2, window))
    button_explore2 = tk.Button(window, text = "Browse Files", command=lambda:browseFiles(file_select2))
    button_clear2 = tk.Button(window, text = "Clear Files", command=lambda:clearFiles(file_select2))
    
    # checkbuttons
    ack_flood = tk.Checkbutton(window, text='Ack Flood',variable=flood_var[0], onvalue=1, offvalue=0)
    dns_flood = tk.Checkbutton(window, text='DNS Flood',variable=flood_var[1], onvalue=1, offvalue=0)
    syn_flood = tk.Checkbutton(window, text='SYN Flood',variable=flood_var[2], onvalue=1, offvalue=0)
    griep_flood = tk.Checkbutton(window, text='Greip Flood',variable=flood_var[3], onvalue=1, offvalue=0)
    greeth_flood = tk.Checkbutton(window, text='Greeth Flood',variable=flood_var[4], onvalue=1, offvalue=0)
    vse_flood = tk.Checkbutton(window, text='VSE Flood',variable=flood_var[5], onvalue=1, offvalue=0)
    http_flood = tk.Checkbutton(window, text='HTTP Flood',variable=flood_var[6], onvalue=1, offvalue=0)
    udpplain_flood = tk.Checkbutton(window, text='UDPplain Flood',variable=flood_var[7], onvalue=1, offvalue=0)
    udp_flood = tk.Checkbutton(window, text='UDP Flood',variable=flood_var[8], onvalue=1, offvalue=0)
    
    check_arr.append(ack_flood)
    check_arr.append(dns_flood)
    check_arr.append(syn_flood)
    check_arr.append(griep_flood)
    check_arr.append(greeth_flood)
    check_arr.append(vse_flood)
    check_arr.append(http_flood)
    check_arr.append(udpplain_flood)
    check_arr.append(udp_flood)

    button_check_all = tk.Button(window, text = "Check All", command=lambda:check_all(flood_var))
    button_check_none = tk.Button(window, text = "Uncheck All", command=lambda:uncheck_all(flood_var))
   
    # set widget placements
    select_label.place(x=-1, y=190)
    analysis_label.place(x=-1, y=35)
    end_label.place(x=-1, y=444)
    output_label.place(x=-1,y=346)
    file_select.place(x=10, y=90)
    label_file_explorer.grid(column = 1, row = 1)
    browse_label.place(x=10, y=40)
    return_label.place(x=10, y=355)
    button_explore.place(x=270, y=47)
    button_clear.place(x=400, y=47)
    button_exit.place(x=450, y=460)
    choose_label.place(x=10, y=200)
    button_analyze.place(x=30, y=460)
    button_explore2.place(x=270, y=362)
    button_clear2.place(x=400, y=362)
    file_select2.place(x=10, y=402)
    
    # set checkbutton placements
    button_check_all.place(x=270, y=207)
    button_check_none.place(x=400, y=207)
    ack_flood.place(x=10, y=250)
    dns_flood.place(x=10, y=280)
    syn_flood.place(x=10, y=310)
    griep_flood.place(x=150, y=250)
    greeth_flood.place(x=150, y=280)
    vse_flood.place(x=150, y=310)
    http_flood.place(x=290, y=250)
    udpplain_flood.place(x=290, y=280)
    udp_flood.place(x=290, y=310)
        
    # let the window wait for any events
    window.mainloop()

if __name__ == '__main__':
	main()