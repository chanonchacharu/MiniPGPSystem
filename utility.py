from Crypto.Util import number
import random

# Function: Calculate gcd two numbers a and b
def gcd(a,b):
    while b != 0: 
        (a,b) = (b, a%b)
    return a

# Get prime number e from the set phi
def generateEfromPhi(phi):
    e = random.randint(2, phi)
    while gcd(e,phi) != 1:
        e = random.randint(2,phi)
    return e

def ExtendedEuclidean(a, b):
    r, r_old = a, b
    s, s_old = 1, 0
    t, t_old = 0, 1

    while r_old != 0:
        quotient = r // r_old
        r, r_old = r_old, r - quotient * r_old
        s, s_old = s_old, s - quotient * s_old
        t, t_old = t_old, t - quotient * t_old

    return r, s, t

def MulInverse(a, m):
    gcd, x, y = ExtendedEuclidean(a, m)
    if gcd != 1:
        return None
    else:
        return (x % m + m) % m

def generateDfromE(e,phi):
    return MulInverse(e,phi)

class KeyGenerator(object):
    def __init__(self, numOfBit):
        self.p = number.getPrime(numOfBit)
        self.q = number.getPrime(numOfBit)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

    def generate_key(self):
        '''
        Return Public Key (e,n) and Private Key (d,n) 
        '''
        e = generateEfromPhi(self.phi)
        d = generateDfromE(e, self.phi)

        return (e, self.n), (d, self.n)

def HexadecimalToBinary(num):
    return bin(int(num,16))[2:]

def BinaryToHexadecimal(num):
    return hex(int(num,2))[2:]

def ByteToBinary(a):
    return ''.join(format(b, '08b') for b in a)

def BinaryToByte(a):
    return bytes([int(a[i:i+8], 2) for i in range(0, len(a), 8)])

if __name__ == "__main__":
    numOfBit = 16
    alice_pu, alice_pr = KeyGenerator(numOfBit).generate_key()
    print(f"Alice:\nPU: {alice_pu}\nPR: {alice_pr}")
    print()
    bob_pu, bob_pr = KeyGenerator(numOfBit).generate_key()
    print(f"Bob:\nPU: {bob_pu}\nPR: {bob_pr}")