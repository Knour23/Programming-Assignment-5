import random
from math import gcd

class BigInt:
    def __init__(self, value):
        if isinstance(value, str):
            self.digits = list(map(int, reversed(value)))
        elif isinstance(value, int):
            self.digits = list(map(int, reversed(str(value))))
        else:
            raise ValueError("BigInt accepts only strings or integers.")

    def __str__(self):
        return ''.join(map(str, reversed(self.digits)))

    def __add__(self, other):
        a, b = self.digits, other.digits
        result = []
        carry = 0
        for i in range(max(len(a), len(b))):
            digit_sum = carry
            if i < len(a):
                digit_sum += a[i]
            if i < len(b):
                digit_sum += b[i]
            carry, digit = divmod(digit_sum, 10)
            result.append(digit)
        if carry:
            result.append(carry)
        return BigInt(''.join(map(str, reversed(result))))

    def __mul__(self, other):
        a, b = self.digits, other.digits
        result = [0] * (len(a) + len(b))
        for i in range(len(a)):
            carry = 0
            for j in range(len(b)):
                result[i + j] += carry + a[i] * b[j]
                carry, result[i + j] = divmod(result[i + j], 10)
            result[i + len(b)] += carry
        while len(result) > 1 and result[-1] == 0:
            result.pop()
        return BigInt(''.join(map(str, reversed(result))))

    def __mod__(self, modulus):
        result = 0
        base = 1
        for digit in reversed(self.digits):
            result = (result + digit * base) % modulus
            base = (base * 10) % modulus
        return result

    def __pow__(self, exp, mod):
        base = int(str(self))
        result = pow(base, int(exp), int(mod))
        return BigInt(str(result))


def generate_prime(digits):
    while True:
        num = random.randint(10**(digits - 1), 10**digits - 1)
        if is_prime(num):
            return num


def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x in {1, n - 1}:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_keygen(digits):
    p = generate_prime(digits)
    q = generate_prime(digits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = pow(e, -1, phi)
    return (e, n), (d, n)


def rsa_encrypt(message, pubkey):
    e, n = pubkey
    m = BigInt(message)
    return m ** e % n


def rsa_decrypt(ciphertext, privkey):
    d, n = privkey
    c = BigInt(ciphertext)
    return c ** d % n


if __name__ == "__main__":
    # Generate keys
    public_key, private_key = rsa_keygen(50)  # 50-digit primes
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Encrypt and decrypt a message
    message = input("Enter a message to encrypt (as a number): ")
    encrypted = rsa_encrypt(message, public_key)
    print("Encrypted:", encrypted)
    decrypted = rsa_decrypt(str(encrypted), private_key)
    print("Decrypted:", decrypted)
