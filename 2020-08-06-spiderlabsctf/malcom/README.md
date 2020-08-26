# Malcom

In the challenge we got [malcom.py](malcom.py) and [ciphertext](ciphertext).

Looking at the encryption program we can see that two random keys are generated and then used to doubly encrypt the flag. Lucky for us the keysize is only 24 bits as the random
number is '&' with 0xFFFFFF.

```python
def randkey():
    random_number = randint(0, int(time())) & 0xFFFFFF
    key = pack('<I', random_number)
    return pad(key)

def encrypt(data, key1, key2):
    data = pad(data)

    c1 = AES.new(key1, AES.MODE_ECB)
    enc = c1.encrypt(data)

    c2 = AES.new(key2, AES.MODE_ECB)
    return c2.encrypt(enc)


secret = 'Well done! your flag is: <redacted>'
key1 = randkey()
key2 = randkey()

ct = encrypt(secret, key1, key2)
```

At first I attempted to bruteforce the flag by performing ~16mil decryptions each with another ~16mil decryptions which resulted in an O<sup>2</sup> time complexity which ultimately failed (somthing like 32 years of cracking time with my rig).
After a bit of research I found that given a key size of 'k' and knowledge of part of the plaintext, the time to break doubly encrypted data is in fact 2<sup>k</sup> + 2<sup>k</sup> = 2<sup>k+1</sup> 
**NOT** 2<sup>k</sup> * 2<sup>k</sup> = 2<sup>k+k</sup> by using something called a **meet-in-the-middle** attack.

A meet-in-the-middle attack works by performing 2<sup>k</sup> decryptions on the ciphertext, 2<sup>k</sup> encryptions on a portion of the paintext, and then taking both lists
and finding the two keys that give similar blocks of ciphertext.

For Example:
```python
ct = '1ae4c56852fde8ca7ec9823587550aa2be3c839caa0a565c6a299e7a5e2cc9998302960abc778ba3ee3c8ad0518b1edae12e4a387fbfcfa25e7b0e249a17ff61'
pt = 'Well done! your flag is: <redacted>'
```

Will generate entries (middle-ciphertext[:20]:key):
```
629ebe03d08600144418:13896922
629ebe03d08600144418:15626165
```

Then simply use the two keys (15626165,13896922) to doubly decrypt the ciphertext

Well done! your flag is: `FLAG-dcab2ae52644a3563fd7daa4adbba3d6`

