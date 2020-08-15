from Crypto.Util.number import *
from functools import reduce
import operator

def comb(n, k):
	if k > n :
		return 0
	k = min(k, n - k)
	u = reduce(operator.mul, range(n, n - k, -1), 1)
	d = reduce(operator.mul, range(1, k + 1), 1)
	return u // d

def find_m(c):
	i = 0
	m = 0
	while c > 0:
		if c % 3 == 1:
			m += 2 ** i
			c -= 1
		elif c % 3 == 2:
			m += (find_m(c-2)-1)*(2 ** i)
			break
		c //= 3
		i += 1
	return m

enc = 5550332817876280162274999855997378479609235817133438293571677699650886802393479724923012712512679874728166741238894341948016359931375508700911359897203801700186950730629587624939700035031277025534500760060328480444149259318830785583493
m = find_m(enc)
b = bin(m)[2:]
n = len(b)
pos = []
for i,j in enumerate(b[::-1]):
	if j == '1':
		pos.append(i)
pos = pos[:-1]  #Excluding last high bit
msg = 0
k = 1
for i in pos:
	msg += comb(i,k)
	k += 1
print(long_to_bytes(msg))
