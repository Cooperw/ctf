This challenge involved using predictable AES.ECB blocks to reverse engineer an encrypted cookie to take control of an "admin" field and set it to "1". The python Flask app contained an endpoint for setting the color value within the session cookie, craft payloads to discover the appropriate blocks and then use those to construct a new cookie


Known cookie contents: 
```
_id=12345678&admin=0&color=ffff00&
```

Sample Cookie
```
session 7a736eda3aa4774894bd61f6bf717a7042423aa9a1b5afc6a7ea479a1d0bd98b /
```

Start with padding to isolate the ECB blocks
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (http://52.59.124.14:10017/color/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
_ i d = 1 2 3 4 5 6 7 8 & a d m  i n = 0 & c o l o r = A A A A A  A A A A A A A A A A A A A A A A  A A A A A A A A A A A A A A A A 
7a736eda3aa4774894bd61f6bf717a70 42423aa9a1b5afc6a7ea479a1d0bd98b 3b17f85c66c882497639fb6a2a3c9a8c 3b17f85c66c882497639fb6a2a3c9a8c e33815146a57b246e08907f12b6b97e4
```

Feed in "in=1" and pad the rest of that ECB block with "&" (goal is to obtain the 484 block)
The extra "&" were to prevent server execution/parsing errors when reading the cookie, a byproduct is that we will end up creating a new cookie field named "in". We need to ensure that we retain the color field for proper execution.
```
AAAAAin=1&&&&&&&&&&&& (http://52.59.124.14:10017/color/AAAAAin=1&&&&&&&&&&&&)
_ i d = 1 2 3 4 5 6 7 8 & a d m  i n = 0 & c o l o r = A A A A A  i n = 1 & & & & & & & & & & & &
7a736eda3aa4774894bd61f6bf717a70 42423aa9a1b5afc6a7ea479a1d0bd98b 4849ea5ba0f1126ddf0887b7ef6fa200 e33815146a57b246e08907f12b6b97e4
```

Assemble pieces in desired order (inject the 484 payload block into the sequence)
```
_ i d = 1 2 3 4 5 6 7 8 & a d m  i n = 1 & & & & & & & & & & & &  i n = 0 & c o l o r = A A A A A  A A A A A A A A A A A A A A A A 
7a736eda3aa4774894bd61f6bf717a70 4849ea5ba0f1126ddf0887b7ef6fa200 42423aa9a1b5afc6a7ea479a1d0bd98b 3b17f85c66c882497639fb6a2a3c9a8c e33815146a57b246e08907f12b6b97e4
```

Combine into cookie
```
7a736eda3aa4774894bd61f6bf717a704849ea5ba0f1126ddf0887b7ef6fa20042423aa9a1b5afc6a7ea479a1d0bd98b3b17f85c66c882497639fb6a2a3c9a8ce33815146a57b246e08907f12b6b97e4
```

Override the cookie in the browser and refresh the page!
```
ENO{W3B_H4S_Crypt0!}
```
