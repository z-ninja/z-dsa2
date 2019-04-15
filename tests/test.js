const zdsa = require("../")({CELL_SIZE_S:32,MIN_SHARE_COUNT:16});
const crypto = require("crypto");


var keys = zdsa.keyPairNew();
var msg = crypto.randomBytes(32);
var signature = zdsa.sign(keys.private, msg);
console.log("zdsa",keys.private.length,keys.public.length,signature.length);
console.log(zdsa.verify(keys.public, msg, signature)!==0);

var start = Date.now();
for(var i=0;i<1000;i++){
msg = crypto.randomBytes(32);
signature = zdsa.sign(keys.private, msg);
if(zdsa.verify(keys.public, msg, signature)===0){
 console.log("invalid signature",r);
break; 
}
}
var now = Date.now();
console.log("1000 signing and verifications in",now-start,"milliseconds");




