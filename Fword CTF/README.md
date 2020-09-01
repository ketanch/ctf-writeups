# **Fword CTF 2020**  
## Schuuuuush 
### Points : 499
### Flag : FwordCTF{Mehdi_knows_alot_about_Schmidt-samoa_but_is_it_better_than_RSA?}
Challenge :  
chall.py
```
from Crypto.Util.number import getPrime, bytes_to_long
from gmpy2 import gcd
from sympy import nextprime
from secret import flag,BITS

func = lambda x, bits : x**12 + (x & (2**(bits//2)-1))

def PrimeGen(bits):
	pr = getPrime(bits)
	p = nextprime(func(pr,bits))
	qr = getPrime(bits)
	q = nextprime(func(qr,bits))
	return p, q	 

p,q = PrimeGen(BITS)
n = pow(p,2)*q
c = pow(bytes_to_long(flag),n,n)
```
output.txt  
```
{n:12838608941410176012340339820403664970195097778934681712442256463398083779434726523727337362548077816498494779634767166505330187300918251880884095061402948317273750734359805972172291702330170769941722135721254301797373910929209389934028023681108705224982459292501258476944977718620453591356928959990356039307404842140809349783009344965382885388230201854950013659777184155467116001057622057495928115145173039957373456282486463372004327112269636005406697476348929483659820840611834738925620510057932617464105487439853704904186236400811201279769590508776546485548532642090814468965154747150494170880560045656388451020601,c:7050573356706442469683539123500770567737718645915519903139491762612445024317075069313476689401710155602518263519640817376340655413504872884207299668765616582487443371872620836280094522785104280556591702549809637571584448052503290838137680131373345867011613789868193526268278698789425705452031352784824472345055152400817574925351780178219492978046243297746285248144022980576645706737451329739930693946984047194996318634833190911615115111633867444659880674198115147887713534332191601313998075654936972222500960455343228277446386199666597757275851736103707318615905859809209855195657904316567873616670459334137634275173}
```   
**Solution :**  
First of all we find the **BITS** variable value.  
Let's say **getPrime(bits)** generate a prime **x**. Bit length of **n** is 2047 and **n** is effectively *x<sup>36</sup>*. So bit length of **x** should be around ***(2047/36)±1***. Take some random values for these bit lengths and compare it to n, and it can be easily concluded that **BITS** is **57**.  
Now let's say:  

*p = nextprime(func(x1))*  
*q = nextprime(func(x2))*  

So **p** and **q** are effectively:  

*p = x1<sup>12</sup>+k1*  
*q = x2<sup>12</sup>+k2* , where k1 and k2 are constants << x<sup>12</sup>

Now basically we need to calculate **x1** and **x2**.  
Let's analyse what the **12th** root of **n** gives:  

*n<sup>1/12</sup>   =  &nbsp; p<sup>1/6</sup> \* q<sup>1/12</sup>*  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; =  &nbsp; *x1<sup>2</sup> (1 + k1 / (6 \* x1<sup>12</sup>)) \* x2 (1 + k2 / (6 \* x2<sup>12</sup>))* &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[Using binomial approximation]  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; =  &nbsp; *(x1<sup>2</sup> + k1 / (6 \* x1<sup>10</sup>)) \* (x2 + k2 / (6 \* x2<sup>11</sup>))*  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; =  &nbsp; *(x1<sup>2</sup> \* x2 + y)* &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[y is the rest of the product and it is << 1]  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; =  &nbsp; *x1<sup>2</sup> \* x2* &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[We are dealing only in integer values]  

WTF ? **12th** root of **n** gives **us x1<sup>2</sup> \* x2**  
<pre>>>> _product = iroot(n, 12)[0]    [Using gmpy2]  
# _product = 2199766062441797577302949884026507797060867827397893 </pre>  
Factor **_product** using [factordb.com](http://factordb.com/index.php) and voila:  
>2199766062441797577302949884026507797060867827397893 = 132788897400365081<sup>2</sup> \* 124753565845126613  

As we have **x1** and **x2**, calculate primes and eventually flag.  
Full solution is avaliable at [shh.py](https://github.com/ketanch/ctf-writeups/blob/master/Fword%20CTF/shh.py)
