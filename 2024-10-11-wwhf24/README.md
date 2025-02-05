# Wild West Hacking Fest 2024 Badge Challenge


Team
- Stephen Glombicki / Logix (@ladderlogic)
- Viktor Yakovlyev / chickn nuggies (@chickinnuggies)
- Jon Sullivan / vort (@vort4282)
- Rob Sullivan (@rsulliva)
- Cooper Wiegand / shiloh (@cw0)

## Sections

- [Challenge 1 | The UFO](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#challenge-1--the-ufo)
- [Challenge 2 | Serial](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#challenge-2--serial)
- [Challenge 3 | Morse](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#challenge-3--morse)
- [Challenge 4 | Mystery Signal](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#challenge-4--mystery-signal)
- [Bonus Points!](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#bonus-points-100)

## Intro
Badge Website & Leaderboard: https://hardwarelabs.io/ (also 'strings-able' from firmware)

_todo: intro, setup, cmds to dump initial firmware_

We discovered the following data by manually scrolling through firmware but running the following cmd on a firmware dump will give you an S3 bucket containing the official badge binary, WIFI creds for the badge network if you are interested in spinning up an access point at home, and the connection data for MQTT
```bash
strings wwhf2024.bin | grep "\.com" -A 4
```

Firmware: https://wwhf2024.s3.amazonaws.com/v2/wwhf2024.bin

WIFI:
```bash
WWHF Badges # SSID
77HackTheEsp3too@ # Password
```

MQTT:
```bash
w6e1deed.ala.us-east-1.emqxsl.com # url
broadcast/action # channel
events/device # channel
badges # username
TPY_net1pvg*ywf.cjk # password
```

## Challenge 1 | The UFO

### Steps to solve
1. Begin by powering your badge and then recording the LED sequences flashing on the UFO.

2. Transcribe the 8 LEDS to binary strings
```
01010011
01001001
01000111
01111011
01100011
00110100
01101110
01110100
01011111
01110011
01110100
00110000
01110000
01011111
01110100
01101000
00110011
01011111
01110011
00110001
01100111
01101110
00110100
01101100
01111101
```

3. Construct a CyberChef recipe: FromBinary_8
https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)&input=MDEwMTAwMTEKMDEwMDEwMDEKMDEwMDAxMTEKMDExMTEwMTEKMDExMDAwMTEKMDAxMTAxMDAKMDExMDExMTAKMDExMTAxMDAKMDEwMTExMTEKMDExMTAwMTEKMDExMTAxMDAKMDAxMTAwMDAKMDExMTAwMDAKMDEwMTExMTEKMDExMTAxMDAKMDExMDEwMDAKMDAxMTAwMTEKMDEwMTExMTEKMDExMTAwMTEKMDAxMTAwMDEKMDExMDAxMTEKMDExMDExMTAKMDAxMTAxMDAKMDExMDExMDAKMDExMTExMDE

_The flag is also visible in some tools like IDA or Ghidra but it not easily 'strings-able' thanks to some obfuscation. Some of my team members found the flag via firmware before we joined forces._

## Challenge 2 | Serial

1. Plug your badge into a computer via usb-c and utilize a serial monitor of your choice to monitor messages.
```bash
ls /dev/tty.* # use this cmd to get a list of connected usb devices
screen /dev/tty.usbserial-110 115200
```

2. The badge will periodically dump a base64 payload over serial (you can also extract this payload from the firmware via strings, xxd, manual inspection, etc)

```
I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdHJpbmcuaD4KI2luY2x1ZGUgPHN0ZGxpYi5oPgoKdm9pZCByKGNoYXIgKnMsIGludCBzaGlmdCkgewogICAgZm9yIChpbnQgaSA9IDA7IHNbaV07IGkrKykgewogICAgICAgIGlmIChzW2ldID49ICdBJyAmJiBzW2ldIDw9ICdaJykgc1tpXSA9ICgoc1tpXSAtICdBJyArIHNoaWZ0KSAlIDI2KSArICdBJzsKICAgICAgICBlbHNlIGlmIChzW2ldID49ICdhJyAmJiBzW2ldIDw9ICd6Jykgc1tpXSA9ICgoc1tpXSAtICdhJyArIHNoaWZ0KSAlIDI2KSArICdhJzsKICAgIH0KfQoKaW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKmFyZ3ZbXSkgewogICAgaWYgKGFyZ2MgIT0gMikgcmV0dXJuIDE7CiAgICBpbnQgc2hpZnQgPSBhdG9pKGFyZ3ZbMV0pOwogICAgY2hhciBmW10gPSAiRlZUe3JMcl90MF8zaTNlbGp1M2UzfSI7CiAgICByKGYsIHNoaWZ0KTsKICAgIHByaW50ZigiJXNcbiIsIGYpOwogICAgcmV0dXJuIDA7Cn0K
```

3. Decode the payload with base64
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void r(char *s, int shift) {
    for (int i = 0; s[i]; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = ((s[i] - 'A' + shift) % 26) + 'A';
        else if (s[i] >= 'a' && s[i] <= 'z') s[i] = ((s[i] - 'a' + shift) % 26) + 'a';
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    int shift = atoi(argv[1]);
    char f[] = "FVT{rLr_t0_3i3elju3e3}";
    r(f, shift);
    printf("%s\n", f);
    return 0;
}
```
_optional path: dump from firmware instead of waiting for serial_
```bash
strings wwhf2024.bin | awk 'length($0) > 200' | base64 -d
```

4. ROT13 the "flag"
https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)&input=RlZUe3JMcl90MF8zaTNlbGp1M2UzfQ


## Challenge 3 | Morse

1. Periodically you might notice that your badge's status LED will burst a [morse code sequence](https://youtube.com/shorts/KFdoEGLke7U?feature=share).

2. Using the red led as your baseline with blue as your data, you can extract the following morse code
```
.... .- -.-. -.- - .... . ... .. --. -. .- .-.. ...
```

3. Decode this morse to get the following
```
hackthesignals
```

4. Assuming standard morese caps, the flag is in a non-standard format and is simply
```
HACKTHESIGNALS
```

## Challenge 4 | Mystery Signal

### Phase 1: Tap into MQTT
Using the connection params discovered in the firmware (see top of writeup), we tapped into the MQTT data feeds using the following commands.

Subscribe to broadcasts
```bash
mosquitto_sub -h w6e1deed.ala.us-east-1.emqxsl.com -p 8883 -u "badges" -P "TPY_net1pvg*ywf.cjk" -t "broadcast/#"
```
Subscribe to events
```bash
mosquitto_sub -h w6e1deed.ala.us-east-1.emqxsl.com -p 8883 -u "badges" -P "TPY_net1pvg*ywf.cjk" -t "events/#"
```

### Phase 2: Monitor for broadcasts and eventually capture the "Mystery Signal"
Mystery Signal captured from broadcasts (~every 30 mins when active? never really nailed this down)
```json
{
  "broadcast_event": 12,
  "data": "WfFIAmqjR7RjIJ8fsPdkeUKIUxqrkeZSk9G2+rUKtVv5H1XOmrEWpZjyRUtZVL2AXp4yRFwLkc4C9MgnBwarOA==",
  "date": "10/10/24",
  "time": "06:30PM UTC",
  "message": "Mystery Signal"
}

```

We suspected that the badge was capable of decrypting the data blob in order to process the broadcasts and found that both DES and AES:ECB generate block data consistent with variance and length observed in other MQTT messages. MQTT message data blobs were encrypted in blocks based on input length and we assumed the recurring "==" was padding for message just under 'block size'.

### Phase 3: Dump the RAM, phising for keys!
We examined the firmware for hours looking for anything resembling an AES key but eventually realized that the key must be being loaded into memory if the badge is to decrypt the data blobs so we decided to skip the obfuscation and get keys straight from runtime data.
My teamates discovered datasheets containing esp32-s3 memory segments. Check out these [S3 memory segments from @precurse](https://dl.espressif.com/public/esp32s3-mm.pdf)

_some of these addresses might be a bit off but as long as you target the bulk of SRAM1 you will be good_

To dump a memory segment, use the following command.
```bash
esptool.py dump_mem 0x40380000 393216 out.bin # target memory region
```

### Phase 4A: 'strings' AES Keys (optimal path)
1. While scrolling through memory dumps we found that `63a5fd59688e04a7` was being repeated near each piece of broadcast data, very suspicious to have a 16 character hex string near our encrypted data
```bash
> strings out.bin | awk 'length($0) == 16'
...
271127124610Z0n1
2c65218c96ea4dc8
63a5fd59688e04a7 #this is our "key"
...
```
2. Run a CyberChef:FromHex(63a5fd59688e04a7)
```bash
36336135666435393638386530346137 # our AES key!
```
3. AES Decrypt the mestery signal and parse the hex to find the flag
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Hex','string':'36336135666435393638386530346137'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)From_Hex('Auto')&input=V2ZGSUFtcWpSN1JqSUo4ZnNQZGtlVUtJVXhxcmtlWlNrOUcyK3JVS3RWdjVIMVhPbXJFV3BaanlSVXRaVkwyQVhwNHlSRndMa2M0QzlNZ25Cd2FyT0E9PQ


### Phase 4B: Sliding Windows and bit of Brute (origional path)
After dumping memory and failing to locate valid keys on initial visual inspection (at 3am it did not cross our minds to run a CC:FromHex(hex_string) on the suspicious strings). Instead we aimed to create some wordlists containing all possible keys from the memory dumps and then ran a brute force operation to locate a known Plaintext ("KEEP ALIVE") from a known CipherText ("pxzvI67XgjxDyL0SRR2S2g=="). In theory, if you take every 32 byte segment of data in memory and the AES key is 32 bytes then eventually you will find the key, the sliding window theory genenerates far fewer keys than a traditional brute force solution.

_We tried a combination of 8byte/16byte keys for DES and 16byte/32byte keys for AES_

First make your wordlists
```python
# Keymaker :: GPT-4o
# We ran 3 times to create 8byte, 16byte, and 32byte versions

from timeit import default_timer as timer
from binascii import b2a_hex

#- Config variables 
filename="out.bin"
aes_key_size=16 # 8, 16, 32

#- Variables related to file processing
file_offset=0;
total_keys_found = 0;

start_time = timer()

try:
	#- Open the file
	with open(filename, 'rb') as f:

		#- Read till you find data
		while True:
			#- Seek to the new file offset
			f.seek(file_offset)

			#- Read the keysize number of bytes
			temp_key=f.read(aes_key_size)
			
			#- Exit condition 1: If the read buffer is less than 32 bytes:
			if len(temp_key) < aes_key_size:
				break
			
			#- Exit condition 2: When there are no more bytes to be read from the file:
			if not temp_key:
				break
        
			#- Print the key 
			print(b2a_hex(temp_key))

			#- Increment total number of keys found
			total_keys_found = total_keys_found +1;

			#- Increment file offset one byte at a time
			file_offset=file_offset+1

except KeyboardInterrupt:
	print("User cancelled before end of file")

end_time = timer()
print("Total keys found: ", total_keys_found)
print("Time elapsed = ", end_time-start_time)

```

An example of a keys wordlist
```
ab110000003633613566643539363838
11000000363361356664353936383865
00000036336135666435393638386530
00003633613566643539363838653034
00363361356664353936383865303461
36336135666435393638386530346137
33613566643539363838653034613700
61356664353936383865303461370078
35666435393638386530346137007856
```

Then load in the 16byte and 32byte wordlists into the breaker script.
```python
# Brute AES:ECB_decrypt :: GPT-4o
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

def load_keys(file_path):
    """
    Loads hexadecimal keys from a given file.

    :param file_path: Path to the key file.
    :return: A list of keys in hexadecimal string format.
    """
    keys = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                key = line.strip()
                if key:  # Ensure the line is not empty
                    keys.append(key)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading '{file_path}': {e}")
        sys.exit(1)
    return keys

def is_valid_key(key_bytes):
    """
    Checks if the key length is valid for AES.

    :param key_bytes: The key in bytes.
    :return: Boolean indicating validity.
    """
    return len(key_bytes) in [16, 24, 32]  # AES key sizes: 128, 192, 256 bits

def process_key(hex_key):
    """
    Converts a hexadecimal key string to bytes.

    :param hex_key: The key in hexadecimal string format.
    :return: The key in bytes or None if invalid.
    """
    try:
        key_bytes = bytes.fromhex(hex_key)
        if is_valid_key(key_bytes):
            return key_bytes
        else:
            print(f"Warning: Key '{hex_key}' has invalid length ({len(key_bytes)} bytes). Skipping.")
            return None
    except ValueError:
        print(f"Warning: Key '{hex_key}' is not a valid hexadecimal string. Skipping.")
        return None

def main():
    if len(sys.argv) != 3:
        print("Usage: python aes_decrypt_reverse.py <keys_1.txt> <keys_2.txt>")
        sys.exit(1)
    
    keys_file1 = sys.argv[1]
    keys_file2 = sys.argv[2]
    
    # Load keys from both files
    keys_hex = load_keys(keys_file1) + load_keys(keys_file2)
    total_keys = len(keys_hex)
    print(f"[*] Total keys loaded: {total_keys}")
    
    # Known ciphertext
    known_ct_b64 = "pxzvI67XgjxDyL0SRR2S2g=="
    
    try:
        known_ct_bytes = base64.b64decode(known_ct_b64)
    except Exception as e:
        print(f"Error decoding known ciphertext: {e}")
        sys.exit(1)
    
    # The expected plaintext fragment
    expected_fragment = "KEEP ALIVE"
    
    # Iterate through each key
    for index, hex_key in enumerate(keys_hex, start=1):
        key_bytes = process_key(hex_key)
        if not key_bytes:
            continue  # Skip invalid keys
        
        try:
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(known_ct_bytes)
            # Attempt to unpad the decrypted plaintext
            try:
                decrypted_padded = decrypted_bytes
                decrypted = unpad(decrypted_padded, AES.block_size).decode('utf-8', errors='ignore')
            except ValueError:
                # Padding is incorrect
                decrypted = decrypted_bytes.decode('utf-8', errors='ignore')
            
            # Debug: Print decrypted plaintext
            # print(f"Key {index}: {hex_key} => {decrypted}")
            
            if expected_fragment in decrypted:
                print(f"[*] Key Found at index {index}: {hex_key}")
                print(f"[*] Key (Bytes): {key_bytes}")
                try:
                    # Attempt to decode to ASCII, replacing non-decodable bytes
                    key_ascii = key_bytes.decode('ascii', errors='replace')
                except:
                    key_ascii = "Non-ASCII Key"
                print(f"[*] Key (ASCII): {key_ascii}")
                print(f"[*] Decrypted Plaintext: {decrypted}")
                sys.exit(0)
        except Exception as e:
            print(f"Error processing key '{hex_key}': {e}")
            continue
    
    print("[!] No matching key found in the provided wordlists.")

if __name__ == "__main__":
    main()
```

```
python brute_aes_rev.py keys_2.txt keys_3.txt
[*] Total keys loaded: 982986
[*] Key Found at index 228757: 36336135666435393638386530346137
[*] Key (Bytes): b'63a5fd59688e04a7'
[*] Key (ASCII): 63a5fd59688e04a7
[*] Decrypted Plaintext: KEEP ALIVE
```

Final Decrypt:
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'Hex','string':'36336135666435393638386530346137'%7D,%7B'option':'Hex','string':''%7D,'ECB','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)From_Hex('Auto')&input=V2ZGSUFtcWpSN1JqSUo4ZnNQZGtlVUtJVXhxcmtlWlNrOUcyK3JVS3RWdjVIMVhPbXJFV3BaanlSVXRaVkwyQVhwNHlSRndMa2M0QzlNZ25Cd2FyT0E9PQ

## Bonus Points! (100)

From the firmware we discovered the POST endpoint used by the scanners to claim bounties when an attendee's badge was read via NFC. After playing with the request body and attaching a Bearer token extracted from firmware, we managed to craft the proper requests to grant bounties to any badge!

We had been playing with this endpoint for hours but not until we managed to get some serial log data from a scanner did we realize that the `rfid` field needed to have the uid in a lowercase-no-spaces format. Simply use and NFC reader to capture your badge's NFC UID. A flipper, proxmark, or smartphone with the NFCTools app will do.

```bash
# [POST]
https://hardwarelabs.io/bounties
```
```
Bearer W8nqEekeZ2a4LeXVVuQ2yNYwRrsDYT
```
```json
{
    "mac_address": "EC:DA:3B:5E:4A:14",
    "rfid": "7159d940"
}
```

- todo talk about building MAC wordlists to isolate OUI regions hoping to locate the missing Event 5"

In our quest to grant ourselves "Event 5" we managed to uncover a hidden vendor bounty worth 100 points from scanner EC:DA:3B:5E:17:30 which allowed us to have 26/25 vendor bounties, effectively pushing our scores above the standard achievable score. Thanks @Logix for the discovery, honestly the burst of addrenaline at 1am pushed us to finish solving the final [Challenge 4 | Mystery Signal](https://github.com/Cooperw/ctf/tree/master/2024-10-11-wwhf24#challenge-4--mystery-signal)!

We then developed a script which when given an NFC UID, automatically claims all vendor, stage, and event bounties. We never were able to trigger staff bounties or "event 5" which we later learned was not avaiable due to technical issues.
```python
# claim_bounties.py :: GPT-4o

# usage: python claim_bounties.py 7bdfd941

import requests
import sys
import argparse
import time
import os


'''
export API_BEARER_TOKEN="W8nqEekeZ2a4LeXVVuQ2yNYwRrsDYT"

7bdfd940 shiloh
f4b4d940 logix
7159d940 vort
fcb9d940 alex
a3c9d940 rsulliva
57b4d940 netwarsninja66
8a4fd940 lasso
'''

def main():
    # Define the list of MAC addresses
    mac_addresses = [
        "24:58:7C:C4:AE:4C", # valid, live, unknown
        "C0:4E:30:14:0F:98", # staff bounty 1
        "48:27:E2:76:DF:C8", # staff bounty 2
        "EC:DA:3B:5D:D0:7C",
        # "EC:DA:3B:5D:BF:64" # valid, 0 pts
        "EC:DA:3B:5E:0C:24",
        "EC:DA:3B:5E:0C:34",
        "EC:DA:3B:5E:0C:88",
        "EC:DA:3B:5E:11:D8",
        "EC:DA:3B:5E:11:E8",
        "EC:DA:3B:5E:11:F0",
        "EC:DA:3B:5E:11:F4",
        "EC:DA:3B:5E:12:30",
        "EC:DA:3B:5E:12:34",
        "EC:DA:3B:5E:12:78",
        "EC:DA:3B:5E:12:8C",
        "EC:DA:3B:5E:12:90",
        "EC:DA:3B:5E:12:A8",
        "EC:DA:3B:5E:16:D0",
        "EC:DA:3B:5E:16:F0",
        "EC:DA:3B:5E:1F:80",
        "EC:DA:3B:5E:1F:C8",
        "EC:DA:3B:5E:48:30",
        # "EC:DA:3B:5E:48:74", # valid, 0 pts
        # "EC:DA:3B:5E:4A:14", # valid, 0 pts
        # "EC:DA:3B:5E:4A:18", # valid, 0 pts
        # "EC:DA:3B:5E:4A:D4", # valid, 0 pts
        # "EC:DA:3B:5E:4A:D8", # valid, 0 pts
        "EC:DA:3B:5E:53:F8",
        "EC:DA:3B:5E:6D:48",
        "EC:DA:3B:5E:6D:54",
        "EC:DA:3B:5E:6D:5C",
        "EC:DA:3B:5E:6D:68",
        "EC:DA:3B:5E:6D:70",
        "EC:DA:3B:5E:6D:80",
        "EC:DA:3B:5F:5B:50",
        "EC:DA:3B:5F:FD:90",
        "EC:DA:3B:5F:FD:94",
        "EC:DA:3B:5F:FD:AC",
        "EC:DA:3B:5F:FD:B4",
        "EC:DA:3B:5F:FD:C0",
        "EC:DA:3B:5F:FD:C4",
        "EC:DA:3B:5E:17:30", # unlisted vendor, 100 pts
    ]

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send POST requests to hardwarelabs.io/bounties.')
    parser.add_argument('rfid', type=str, help='RFID value to include in the POST request.')
    args = parser.parse_args()

    rfid = args.rfid

    endpoint = "https://hardwarelabs.io/bounties"

    # Retrieve the Bearer Token from environment variables
    bearer_token = os.getenv('API_BEARER_TOKEN')
    if not bearer_token:
        print("Error: API_BEARER_TOKEN environment variable not set.")
        sys.exit(1)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer_token}"
    }

    success_count = 0
    error_count = 0

    for index, mac in enumerate(mac_addresses, start=1):
        payload = {
            "mac_address": mac,
            "rfid": rfid
        }

        try:
            response = requests.post(endpoint, json=payload, headers=headers)
            if response.status_code == 201:
                success_count += 1
                print(f"SUCCESS [{index}/{len(mac_addresses)}]: MAC {mac} - Status Code: {response.status_code}")
            else:
                error_count += 1
                print(f"ERROR   [{index}/{len(mac_addresses)}]: MAC {mac} - Status Code: {response.status_code} - Response: {response.text}")
        except requests.exceptions.RequestException as e:
            error_count += 1
            print(f"EXCEPTION[{index}/{len(mac_addresses)}]: MAC {mac} - {e}")

        # Rate limiting
        if index < len(mac_addresses):
            time.sleep(0.1)

    print("\n=== Summary ===")
    print(f"Total Requests: {len(mac_addresses)}")
    print(f"Successful (201): {success_count}")
    print(f"Failed: {error_count}")

if __name__ == "__main__":
    main()
```
