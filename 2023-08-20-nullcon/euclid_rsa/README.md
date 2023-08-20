Given:
- Ciphertext (ct)
- Mystery "Magic" Components [a,b,c,d]
- Clues pointing to sum of squares affecting RSA

I managed to locate a white paper on attempting to break RSA via Factorizing Semi-Primes!

Mathematical Attack of RSA by Extending the Sum of Squares of Primes to Factorize a Semi-Prime
https://www.mdpi.com/2297-8747/25/4/63

After a ton of reading and lots of confusion, I managed to conjure together a script that
- started with [a,b,c,d]
- calculated components [A,B,C,D] in accordance with the forumala for k1,2 presented in the paper
- simplified fractional groups of the semi-prime factors
- calculated the sum of squares for each of the semi-prime factors
- calculated the RSA components p,q,n,x,e,d,kp,ks
- ran an encryption/decryption test with my keys
- decrypted the ciphertext to obtain the flag!

```
ENO{Gauss_t0ld_u5_th3r3_1s_mor3_th4n_on3_d1men5i0n}
```
