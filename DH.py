import random
from Crypto.Util import number
from RSA import EfficientModularExpo

# Modification, add dictionary in the case of sending to multiple parties? 
class DiffieHellmanConnection(object):
    def __init__(self, public_generator, public_prime, private_key):
        self.public_generator = public_generator # alpha
        self.public_prime = public_prime # q
        self.private_key = private_key # X
        self.public_key = self.generate_public_key() # Y
        self.shared_secret_key = None # K
    
    def generate_public_key(self):
        '''
        Compute alpha ** X mod q
        '''
        self.public_key =  EfficientModularExpo(self.public_generator, self.private_key, self.public_prime)
        return self.public_key

    def compute_shared_secret_key(self, DHCboj_public_key):
        '''
        Compute alpha (of another party) ** X mod q
        '''
        self.shared_secret_key = EfficientModularExpo(DHCboj_public_key, self.private_key, self.public_prime)
        return self.shared_secret_key 
    
    def generate_random_bytes(self, num_bytes):
        '''
        Generate a stream of random bytes using the shared secret key as a seed
        '''
        if self.shared_secret_key is None:
            raise ValueError("Shared secret key has not been computed yet.")
        
        # Use the shared secret key as a seed to a PRNG
        random.seed(self.shared_secret_key)
        
        # Generate the requested number of random bytes
        return bytes([random.randint(0, 255) for _ in range(num_bytes)])


if __name__ == "__main__":
    # Test Case: Alice and Bob
    '''
    The public generator is any prime number between 2 and (public_prime - 1) and 
    it must be primitive root of public_prime
    '''
    public_prime = number.getPrime(16)
    public_generator = None
    for g in range(2, public_prime):
        if pow(g, (public_prime - 1) // 2, public_prime) != 1 and pow(g, public_prime - 1, public_prime) == 1:
            public_generator = g

    sender_private = number.getPrime(16)
    receiver_private = number.getPrime(16)
    alice = DiffieHellmanConnection(public_generator, public_prime, sender_private)
    bob = DiffieHellmanConnection(public_generator, public_prime, receiver_private)

    alice_shared_secret_key = alice.compute_shared_secret_key(bob.public_key)
    bob_shared_secret_key = bob.compute_shared_secret_key(alice.public_key)

    if alice.shared_secret_key  == bob.shared_secret_key:
        print(f"Same Session Key: {alice.shared_secret_key}")
        print(f"Type of: {type(alice.shared_secret_key)}") # Convert int into bits
    # This shared secret key can be used between the two parties (Alice and Bob) as Session Key
    btye_sessionKey = alice.generate_random_bytes(16)
    print(f"btye_sessionKey: {btye_sessionKey}")
    print(f"Decimal Session Key: {int.from_bytes(btye_sessionKey, byteorder='big')}")