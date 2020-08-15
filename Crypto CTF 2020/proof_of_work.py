#USAGE : python proof_of_work.py host port

from pwn import *
from hashlib import *
import string
import sys

def get_random_string(length):
    letters = string.ascii_lowercase+string.ascii_uppercase+'0123456789'
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

dic = {'sha256':sha256, 'md5':md5, 'sha384':sha384,'sha224':sha224,'sha512':sha512,'sha1':sha1}
conn = remote(sys.argv[1],sys.argv[2])
conn.recvuntil(b'such that ')
algo = conn.recvuntil(b'(')[:-1].decode()
conn.recvuntil(b'= ')
end_hash = conn.recvuntil(b' ')[:-1].decode()
conn.recvuntil(b'= ')
l = int(conn.recvuntil(b'\n')[:-1].decode())
print("Algorithm : ", algo)
print("End value to match : ", end_hash)
print("Length of string : ", l)
while True:
    st = get_random_string(l)
    if dic[algo](st.encode()).hexdigest().endswith(end_hash):
        print("String Found : ", st)
        break
conn.interactive()
conn.close()
