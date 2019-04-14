const zdsa = require("../")();
const crypto = require("crypto");


var keys = zdsa.keyPairNew();
var msg = crypto.randomBytes(32);
var signature = zdsa.sign(keys.private, msg);
console.log("zdsa",keys.private.length,keys.public.length,signature.length);
console.log(zdsa.verify(keys.public, msg, signature));

var start = Date.now();
for(var i=0;i<1000;i++){
msg = crypto.randomBytes(32);
signature = zdsa.sign(keys.private, msg);
if(!zdsa.verify(keys.public, msg, signature)){
 console.log("invalid signature");
break; 
}
}
var now = Date.now();
console.log("1000 signing and verifications in",now-start,"milliseconds");
