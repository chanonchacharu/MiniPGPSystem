import math
from utility import KeyGenerator


# Utility Function
def binaryToDecimal(a):
    return int(a, 2)

def decimalToBinary(num):
    return bin(int(num))[2:]

def EfficientModularExpo(a,m,n):
    
    bits = decimalToBinary(m) # Convert decimal to binary
    d = 1
    for bi in bits:
        d = d*d % n
        if bi != "0":
            d = (d*a) % n      
    return d

class RSAAlgorithm(object):
    def __init__(self):
        pass

    def RSAEncryption(self, binaryBitSeq, encryptionKey):
        e, n = encryptionKey

        plainBlockSize = math.floor(math.log(n,2))
        
        if len(binaryBitSeq) % plainBlockSize != 0:
            binaryBitSeq += "1"
            binaryBitSeq += "0" * (plainBlockSize - len(binaryBitSeq) % plainBlockSize)
        
        binaryBlock = []
        for i in range(0, len(binaryBitSeq), plainBlockSize):
            binaryBlock.append(binaryBitSeq[i:plainBlockSize + i])
        
        decimalBlock = []
        for i in range(len(binaryBlock)):
            decimalBlock.append(binaryToDecimal(binaryBlock[i]))
        
        # Encrpyt with (e,n)
        cipherBlockDecimal = []
        for i in range(len(decimalBlock)):
            cipherBlockDecimal.append(EfficientModularExpo(decimalBlock[i], e, n))
        
        # Convert Ciphered numbers into 8-bits binaries
        cipherBlockBinary = []
        for block in cipherBlockDecimal:
            blockBinary = decimalToBinary(block)
            if len(blockBinary) != plainBlockSize+1:
                blockBinary = ('0'*(plainBlockSize-len(blockBinary)+1)) + blockBinary
            cipherBlockBinary.append(blockBinary)
        
        cipherBitSequence = ""
        for block in cipherBlockBinary:
            cipherBitSequence += block

        cipherBitSequence = "".join(cipherBlockBinary)

        return cipherBitSequence

    def RSADecryption(self, cipherBitSequence, private_key):
        d, n = private_key

        cipherBlockSize = math.floor(math.log(n,2)) + 1
        
        cipherBlock = []
        for i in range(0, len(cipherBitSequence), cipherBlockSize):
            cipherBlock.append(cipherBitSequence[i:cipherBlockSize+i])
        
        decimalCipherBlock = [binaryToDecimal(binary) for binary in cipherBlock]

        # Decrype the each decimal number using PK receiver = (d,n)
        binaryCiperBlock = [EfficientModularExpo(decimal, d, n) for decimal in decimalCipherBlock]

        # Convert decrypted numbers to 7-bits binaries
        converted_binaryBlock = []
        for decimal in binaryCiperBlock:
            binaryBlock = decimalToBinary(decimal)
            if len(binaryBlock) != cipherBlockSize - 1:
                binaryBlock = ("0" * ((cipherBlockSize - 1) - len(binaryBlock))) + binaryBlock
            converted_binaryBlock.append(binaryBlock)
        
        # Remove the padding at the end after creating the binary plaintext
        plaintextSequence = "".join(converted_binaryBlock)
        index = 0
        for i in range(len(plaintextSequence)-1, 0, -1):
            if plaintextSequence[i] == "1":
                index = i
                break
        adjusted_plaintextSequence = plaintextSequence[0:index]

        return adjusted_plaintextSequence

if __name__ == "__main__":
    numOfBit = 16
    alice_pu, alice_pr = KeyGenerator(numOfBit).generate_key()
    print(f"Alice:\nPU: {alice_pu}\nPR: {alice_pr}")
    print()
    bob_pu, bob_pr = KeyGenerator(numOfBit).generate_key()
    print(f"Bob:\nPU: {bob_pu}\nPR: {bob_pr}")
    print()

    rsa = RSAAlgorithm()
    print(f"Original: {1011000110101011}")
    # Use Public to Encrypt
    print(f"Encrypted: {rsa.RSAEncryption('1011000110101011',alice_pu)}")
    # Use Private to Decrypt
    print(f"Decrypted: {rsa.RSADecryption(rsa.RSAEncryption('1011000110101011',alice_pu),alice_pr)}")
