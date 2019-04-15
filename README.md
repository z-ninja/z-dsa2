# z-dsa2
Z-2 Digital Signature Algorithm - Hash Based

One time signature schema.

# INSPIRAITON:
Shamir's secret threshold and Lamport signature schema.

# GOAL:
Keep security while reducing keys and signature size.

# INSTALL
```javascript
npm i z-dsa2
```
Example
```javascript
const zdsa = require("z-dsa2")();
const crypto = require("crypto");
var keys = zdsa.keyPairNew();
var msg = crypto.randomBytes(32);
var signature = zdsa.sign(keys.private, msg);
console.log("zdsa",keys.private.length,keys.public.length,signature.length);
console.log(zdsa.verify(keys.public, msg, signature));
```

# Notice
This version of z-dsa is more sucure then previous one.


# Paper - Simplified
We need at least one hash function or two different.

First hash function should be a strongerone( we will use sha256 marked as HLG), 

second can be weak as even md5( we will mark it as HSM).

First hash function will be used to generate signature, while second is used to generate public key.

I will show example with a minimum security.

We will define few constants.

CELL_SIZE_L -> as 32 // size of first hash function output in bytes like sha256

CELL_SIZE_S -> as 16 // size of second hash function output in bytes like md5

HASH_COUNT -> as 64 // number of hashes used to generate private key

so PRIVATE_KEY_BYTES = CELL_SIZE_L*HASH_COUNT /// size of private key in bytes - 2048 for our case

PUBLIC_KEY_BYTES = CELL_SIZE_S*HASH_COUNT /// size of public key in bytes - 1024 for our case

SIGNATURE_BYTES = CELL_SIZE_L * CELL_SIZE_L /// size of signature in bytes - 1024 for our case

MIN_SHARE_COUNT = 15 in our case
# Key Creation
Pk,Sk = public key, private key
I = share index
Allice will generate random bytes (Nonce) of CELL_SIZE_L size and will generate Shamir's threshold share

with HASH_COUNT shares and MIN_SHARE_COUNT threshold.

Each share must be CELL_SIZE_L+1 size in bytes.

To create private key from shares we exclude first byte(since it is just an index of share) of each share and join all shares together.

That is Allice private key.

To generate public key we hash each share from private key with HLG and HSM hash function together with nonce and joing them together.

HSM(HLG(SK[I]),nonce)

That is Allice public key and she can share it with the world.

# Signing

To create signature we need message M which size can be up to CELL_SIZE_L size in bytes and Allice private key.

She will hash message M with HLG and iterate over each byte then MOD byte value with HASH_COUNT to get our share index I.

HM = HLG(M)

foreach HM as NUM=>B

I = B MOD HASH_COUNT

for the first MIN_SHARE_COUNT bytes, we will make sure to pick unique from Private key Sk and will be assigned to signature as plain text.

Other bytes NUM>MIN_SHARE_COUNT will be assigned in hashed with HLG.

So we make sure there is enough unique shares to recover nonce in verification proces.

Other shares are in hashed to keep them in secret.
That is a signature.

# Verification

To verify signature Bob will need message M,Allice public key Pk and Allice signature S.
Hi will hash message:

HM = HLG(M)
Then will try to recover nonce from first MIN_SHARE_COUNT bytes of HM.

After will iterate again over HM from begin.
For first MIN_SHARE_COUNT bytes will check if:

Pk[I] == HSM(HLG(S[NUM])|Nonce)

for other hashed shares will check if:
Pk[I] == HSM(S[NUM]|Nonce)


If all parts are equal signature is valid.

This way we reveal only MIN_SHARE_COUNT shares in palin text enough to recover Nonce, rest of shares are included hashed
into signature or not incluced at all, at least 50% shares are not included in signature.
With each new signature used by same keys, security will drop down, so you should use keys for one time signature.



