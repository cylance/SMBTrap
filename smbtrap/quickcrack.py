from hashlib import new as hlnew
from hmac import new as hmnew
from Crypto.Cipher import DES
from bitarray import bitarray


"""
This module is a very simple code base to conduct very short and simple cracking of hashes used in SMB authentication.
This script has not been optimized for speed, and should only be used for cracking the most common of passwords.
Developed by Brian Wallace @botnet_hunter
"""

# todo Load dictionary from file
dictionary = {
    "password",
    "",
    "ADMIN",
    "12345",
    "1234",
    "123",
}


def des_7_to_8(i):
    ba1 = bitarray()
    ba1.frombytes(i)
    bai1 = ba1.insert
    [bai1(x, False) for x in [7, 15, 23, 31, 39, 47, 55, 63]]
    return ba1.tobytes()


def try_to_crack_hash(input_hash):
    if "NETLM" in input_hash:
        user, remainder = input_hash.split(":")
        ignore, hash_type, server_challenge, lmhash = remainder.split("$")
        server_challenge = server_challenge.decode('hex')
        lmhash = lmhash.decode('hex')
        for password in dictionary:
            opassword = password
            password = password.upper()
            if len(password) > 14:
                password = password[:14]
            password += "\x00" * (14 - len(password))
            part_1 = password[:7]
            d_1 = DES.new(des_7_to_8(part_1), DES.MODE_ECB)

            part_2 = password[7:]
            d_2 = DES.new(des_7_to_8(part_2), DES.MODE_ECB)

            lm = d_1.encrypt("KGS!@#$%") + d_2.encrypt("KGS!@#$%")

            p_1 = des_7_to_8(lm[:7])
            p_2 = des_7_to_8(lm[7:14])
            p_3 = des_7_to_8(lm[14:] + "\x00\x00\x00\x00\x00")

            pd_1 = DES.new(p_1, DES.MODE_ECB)
            pd_2 = DES.new(p_2, DES.MODE_ECB)
            pd_3 = DES.new(p_3, DES.MODE_ECB)

            if pd_1.encrypt(server_challenge) + pd_2.encrypt(server_challenge) + pd_3.encrypt(server_challenge) == \
                    lmhash:
                return opassword
        pass
    elif "NETNTLM" in input_hash:
        user, remainder = input_hash.split(":")
        ignore, hash_type, server_challenge, ntlmhash = remainder.split("$")
        server_challenge = server_challenge.decode('hex')
        ntlmhash = ntlmhash.decode('hex')
        for password in (i.encode('utf-16le') for i in dictionary):
            lm = hlnew("md4", password).digest()
            p_1 = des_7_to_8(lm[:7])
            p_2 = des_7_to_8(lm[7:14])
            p_3 = des_7_to_8(lm[14:] + "\x00\x00\x00\x00\x00")

            pd_1 = DES.new(p_1, DES.MODE_ECB)
            pd_2 = DES.new(p_2, DES.MODE_ECB)
            pd_3 = DES.new(p_3, DES.MODE_ECB)
            if pd_1.encrypt(server_challenge) + pd_2.encrypt(server_challenge) + pd_3.encrypt(server_challenge) == \
                    ntlmhash:
                return password.decode('utf-16le')
    else:
        user, ignore, domain, server_challenge, nthash, remainder = input_hash.split(":")
        user = user.upper().encode('utf-16le')
        domain = domain.encode('utf-16le')
        server_challenge = server_challenge.decode('hex')
        nthash = nthash.decode('hex')
        remainder = remainder.decode('hex')
        for password in (i.encode('utf-16le') for i in dictionary):
            if hmnew(hmnew(hlnew("md4", password).digest(), user + domain).digest(), server_challenge + remainder).digest() == nthash:
                return password.decode('utf-16le')
    return None
