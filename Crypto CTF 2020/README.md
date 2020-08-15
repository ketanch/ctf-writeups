# **Crypto CTF 2020**  
## Amsterdam  
### Category : Easy, Points : 55
### Flag : CCTF{With_Re3p3ct_for_Sch4lkwijk_dec3nt_Encoding!}
Challenge :  
amsterdam.py
```
#!/usr/bin/env python3

from Crypto.Util.number import *
from functools import reduce
import operator
from secret import flag, n, k

def comb(n, k):
	if k > n :
		return 0
	k = min(k, n - k)
	u = reduce(operator.mul, range(n, n - k, -1), 1)
	d = reduce(operator.mul, range(1, k + 1), 1)
	return u // d 

def encrypt(msg, n, k):
	msg = bytes_to_long(msg.encode('utf-8'))
	if msg >= comb(n, k):
		return -1
	m = ['1'] + ['0' for i in range(n - 1)]
	for i in range(1, n + 1):
		if msg >= comb(n - i, k):
			m[i-1]= '1'
			msg -= comb(n - i, k)
			k -= 1
	m = int(''.join(m), 2)
	i, z = 0, [0 for i in range(n - 1)]
	c = 0
	while (m > 0):
		if m % 4 == 1:
			c += 3 ** i 
			m -= 1
		elif m % 4 == 3:
			c += 2 * 3 ** i
			m += 1
		m //= 2
		i += 1
	return c

enc = encrypt(flag, n, k)
print('enc =', enc)
```
output.txt  
```
enc = 5550332817876280162274999855997378479609235817133438293571677699650886802393479724923012712512679874728166741238894341948016359931375508700911359897203801700186950730629587624939700035031277025534500760060328480444149259318830785583493
```  

**Analysis :**  
Function comb() gives the value of <sup>n</sup>C<sub>k</sub>.  
To generate encrypted text, first of all a variable **m** is generated using message(flag) with bits set 1 at special places and a special least significant bit and then this **m** is converted to **enc** using some basic arithmetic operations.  
So, basically we have to first find ***m*** from the given ***enc*** value and then make use of the positions of bit **1** in ***m*** to proceed way back to flag.  

**Solution :**  
A simple function to find m from enc is:  
```
def find_m(c):
	i = 0
	m = 0
	while c > 0:
		if c % 3 == 1:
			m += 2 ** i
			c -= 1
		elif c % 3 == 2:
			m += (fc(c-2)-1)*(2 ** i)
			break
		c //= 3
		i += 1
	return m
```
and our m is:
```
>>> m = 13037931070082386429043329808978789360911287214189289770230708339088698578551447560972351036453899271623903109387482345515668380476074788749548946464
>>> b = bin(m)[2:]
>>> b
'1000001010000011110111100000110010110010000000001110111100111010111110100110100000111010111000101100000010111010010011000011010001111101000001101010111110000001000000011000001000110010101000000111111111101101111100000000111101001100001110000110101010101110000100111100100001000101100001011111101001010101010000011010101001001000011010100010000011101011100000110110111101110010011000010111010010111000110110011101001000000110001000000010100000011000000011000010101111001011111111000010000100000'
>>> len(b)
493
```  
In binary form, number of bits in m is 493 and this is the value for our **n**.  
Let's look at lsb of m which is **0**. Since this is 0, we can say our message after all reductions should follow: 

> msg < comb(0, k)    #some k, will find it later. If msg > comb(0,k) then lsb would have been 1.

Since comb(0, k) = 0 if k is positive or 1 if k = 0, we have  

> msg < 1

Also msg gets reduced by ***msg -= comb(n - i, k) iff msg >= comb(n-i, k)***, so from this we have  

> msg >= 0    #i.e. msg can never be negative

Combining both we get that at last(after all reductions) **msg** will be 0. So we can represent msg as a sum of these combatorials.  
Now the question arises, which combatorials to combine ??  
Here comes the role of bit positions '1'. Whenever **m** gets reduced by comb(n-i, k), m[i] becomes '1' and k reduces by 1. So whenever we encounter a bit 1 at index 'i' from last, we can write ***m += comb(i,some k)*** and this k incerases by 1 for next value. The positions at which bit '1' appears are (from backwards and excluding last one) :  
```
[5, 10, 15, 16, 17, 18, 19, 20, 21, 22, 24, 27, 28, 29, 30, 32, 34, 39, 40, 48, 49, 56, 58, 66, 70, 71, 78, 81, 83, 84, 85, 88, 89, 91, 92, 96, 97, 98, 100, 103, 105, 106, 107, 109, 114, 115, 118, 121, 122, 123, 125, 126, 127, 128, 130, 131, 133, 134, 140, 141, 142, 144, 146, 147, 148, 154, 158, 160, 162, 163, 168, 171, 174, 176, 178, 180, 181, 187, 189, 191, 193, 195, 198, 200, 201, 202, 203, 204, 205, 207, 212, 213, 215, 219, 224, 227, 228, 229, 230, 233, 238, 239, 240, 242, 244, 246, 248, 250, 251, 256, 257, 258, 263, 264, 267, 269, 270, 271, 272, 281, 282, 283, 284, 285, 287, 288, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 306, 308, 310, 313, 314, 318, 324, 325, 333, 340, 341, 342, 343, 344, 346, 348, 350, 351, 357, 359, 360, 361, 362, 363, 367, 369, 370, 375, 376, 379, 382, 384, 385, 386, 388, 395, 396, 398, 402, 403, 404, 406, 408, 409, 410, 416, 418, 419, 422, 424, 425, 426, 427, 428, 430, 432, 433, 434, 437, 438, 439, 440, 442, 443, 444, 454, 457, 458, 460, 463, 464, 470, 471, 472, 473, 475, 476, 477, 478, 484, 486]
```
Using all this knowledge we can represent msg as:  

*msg = comb(5,k) + comb(10,k+1) + comb(15,k+2)+ ... + comb(484,k+215) + comb(486,k+216)*  

All now left is to find the initial k.  
From the lsb knowledge of **m**, comb(0,k) is 0 if k is positive which means if at last k>=1,  
**msg (which is 0) < comb(0,k) = 0**, <--CONTRADICTION  
So at last k becomes 0, which means k in the first term of msg i.e. comb(5,k) would be 1, as after it it will decrease by 1 and finally become 0 to satisfy our lsb condition. 

Full solution is avaliable at [ams_soln.py](https://github.com/ketanch/ctf-writeups/blob/master/Crypto%20CTF%202020/ams_sol.py)

## Three Ravens 
### Category : Medium, Points : 90
### Flag : CCTF{tH3_thr3E_r4V3n5_ThRe3_cR0w5}
Challenge :  
three_ravens.py
```
#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag

def keygen(nbit):
	while True:
		p, q, r = [getPrime(nbit) for _ in range(3)]
		if isPrime(p + q + r):
			pubkey = (p * q * r, p + q + r)
			privkey = (p, q, r)
			return pubkey, privkey

def encrypt(msg, pubkey):
	enc = pow(bytes_to_long(msg.encode('utf-8')), 0x10001, pubkey[0] * pubkey[1])
	return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)
```
output.txt:
```
pubkey = (1118073551150541760383506765868334289095849217207383428775992128374826037924363098550311115755885268424829560194236035782255428423619054826556807583363177501160213010458887123857150164238253637312857212126083296001975671629067724687807682085295986049189947830021121209617616433866087257702543240938795900959368763108186758449391390546819577861156371516299606594152091361928029030465815445679749601118940372981318726596366101388122993777320367839724909505255914071, 31678428119854378475039974072165136708037257624045332601158556362844808093636775192373992510841508137996049429030654845564354209680913299308777477807442821)
enc = 8218052282226011897229703907763521214054254785275511886476861328067117492183790700782505297513098158712472588720489709882417825444704582655690684754154241671286925464578318013917918101067812646322286246947457171618728341255012035871158497984838460855373774074443992317662217415756100649174050915168424995132578902663081333332801110559150194633626102240977726402690504746072115659275869737559251377608054255462124427296423897051386235407536790844019875359350402011464166599355173568372087784974017638074052120442860329810932290582796092736141970287892079554841717950791910180281001178448060567492540466675577782909214
```

**Analysis :**  
Instead of 2 primes, 3 primes are used and we are provided the sum and product of these primes as public key.  
Definition of public modulus **N** is also different and here it is product (pqr) * (p+q+r).  
**ASSUMPTION :** I have assumed in my solution that p+q+r > m (message)  
We cannot find p,q,r but we can do some tricks to reduce the modulus from **N** to a smaller value whose totient can be found easily and make use of the fact (p+q+r) is Prime.   

**Solution :**  

*N = (p x q x r) x (p+q+r)*  
*enc = m<sup>65537</sup> mod N*  

As p+q+r is a factor of N, we can reduce above expression to:  
lets say n = (p+q+r), then:  

*enc mod n = m<sup>65537</sup> mod n*  

As n is also prime ( given in question ), its totient is simply n-1 :  

*phi = n-1 = p+q+r-1*  

Now we can compute flag easily:  
```
from Crypto.Util.number import *
from gmpy2 import invert
n = pubkey[1]
enc = enc % n
phi = n-1
e = 65537
d = invert(e,phi)
flag = long_to_bytes(pow(enc,d,n)).decode()
print(flag)
```
