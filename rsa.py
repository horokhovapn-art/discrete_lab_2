import random
class RSA:
    """
    RSA
    """

    def miller_test(self, d, n):
        """
        Miller Rabin test
        """
        a = 2 + random.randint(1, n - 4)
        x = pow(a, d, n)
        if x in (1,n-1):
            return True
        while d != n - 1:
            x = (x * x) % n
            d *= 2
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False

    def is_prime(self, n, k):
        """
        Is prime
        """
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        d = n - 1
        while d % 2 == 0:
            d //= 2
        for _ in range(k):
            if not self.miller_test(d, n):
                return False
        return True

    def gcd(self, a, b):
        """
        Calculate gcd
        """
        while b:
            a, b = b, a % b
        return a

    def generate_keys(self):
        """
        Generate keys
        """
        p = 1
        while not self.is_prime(p,20):
            p = random.randint(2**1023,2**1024)
        q = 1
        while not self.is_prime(q,20):
            q = random.randint(2**1023,2**1024)
        while p == q:
            while not self.is_prime(q,20):
                q = random.randint(2**1023,2**1024)
        n = p*q
        phi = (p - 1) * (q - 1)
        e = 65537
        while self.gcd(e, phi) != 1:
            e += 2
        d = pow(e, -1, phi)
        return (e,n),(d,n)

    def encrypt(self, message, public_key):
        """
        Encrypt message
        """
        e,n = public_key
        return pow(message,e,n)

    def decrypt(self, ciphertext, private_key):
        """
        Decrypt chiper text
        """
        d,n = private_key
        return pow(ciphertext,d,n)
