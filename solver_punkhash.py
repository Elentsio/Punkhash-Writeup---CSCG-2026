import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import *

with open("data.json", "r") as f:
    data = json.load(f)

p = int(data["p"])
factors = [int(x) for x in data["factors"]]
hash_val = int(data["hash"])
enc_flag = bytes.fromhex(data["enc_flag"])

factorsp = factors + [p]

N = 10**50  # weight to penalize

#to center:
shift = 128
sum_factors = sum(factorsp[:16])
shifted_hash = (hash_val - shift * sum_factors) % p

M = Matrix(ZZ, 18, 19)

for i in range(17):
    M[i, i] = 1
    M[i, 18] = N * factorsp[i]

M[17, 17] = 1
M[17, 18] = -N * shifted_hash

R = M.LLL()

aes_key_bytes = []
for row in R:
    if row[18] == 0:
        if row[17] == -1:
            row = [-x for x in row]
        
        shifted_preimage = list(row[:16])

        # shifting back the bytes of preimage
        aes_key_bytes = [int(x + shift) for x in shifted_preimage]
        
        # checking validity of the result (preimage)
        check_sum = sum(factorsp[i] * aes_key_bytes[i] for i in range(16)) % p
        
        if check_sum == hash_val:
            print(aes_key_bytes)
            break

if not aes_key_bytes:
    print("Failed to recover preimage.")
    exit(1)

# decryption using the preimage bytes as key for AES (mode ECB)
key = bytes(aes_key_bytes)
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(enc_flag), 16).decode()
print(flag)
#dach2026{r3duc3_m3_b4by_0n3_m0r3_t1m3_5a3d66ae5ef12bb5}
