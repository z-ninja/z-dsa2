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











