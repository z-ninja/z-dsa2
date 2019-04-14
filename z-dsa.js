
const crypto = require('crypto')
const assert = require('assert')
const tss_1 = require("@stablelib/tss");

module.exports = (options)=>{
  options = options|| {};
  var CELL_SIZE_L = options.CELL_SIZE_L?parseInt(options.CELL_SIZE_L):32; /// 32 for sha256, 64 for sha512
  var CELL_SIZE_S = options.CELL_SIZE_S?parseInt(options.CELL_SIZE_S):16; /// 16 for md5, 32 for sha256, 64 for sha512
  var HASH_COUNT = options.HASH_COUNT?parseInt(options.HASH_COUNT):64;/// max 255
   var MIN_SHARE_COUNT = options.MIN_SHARE_COUNT?parseInt(options.MIN_SHARE_COUNT):16;
  if(isNaN(CELL_SIZE_L)){
    throw new Error("CELL_SIZE_L must be an number");
  }
  if(isNaN(CELL_SIZE_S)){
    throw new Error("CELL_SIZE_S must be an number");
  }
  if(isNaN(HASH_COUNT)){
    throw new Error("HASH_COUNT must be an number");
  }
  if(isNaN(MIN_SHARE_COUNT)){
    throw new Error("MIN_SHARE_COUNT must be an number");
  }
  
  if(CELL_SIZE_L*2<HASH_COUNT){
    throw new Error("HASH_COUNT must be at least CELL_SIZE_L * 2");
  }
  if(MIN_SHARE_COUNT>CELL_SIZE_L){
   throw new Error("MIN_SHARE_COUNT maximum valude should be equal to CELL_SIZE_L:",CELL_SIZE_L);
  }
  
 
  
  var PRIVATE_KEY_BYTES = CELL_SIZE_L*HASH_COUNT; 
  var PUBLIC_KEY_BYTES = CELL_SIZE_S*HASH_COUNT;
  var SIGNATURE_BYTES = CELL_SIZE_L * CELL_SIZE_L;
  
  var algL;
  switch(CELL_SIZE_L){
    case 32:
      algL = "sha256";
      break;
    case 64:
      algL = "sha512";
      break;
    default:
      throw new Error("Invalid L hash");
    
  }
  var algS;
  
   switch(CELL_SIZE_S){
     case 16:
       algS = "md5";
       break;
     case 32:
       algS = "sha256"
       break;
     case 64:
       algS = "sha512"
       break;
     default:
       throw new Error("Invalid S hash");
  }
  function eachByte(message,number, iter) {
  for(var i = 0; i < message.length; i++) {
    if(iter(message[i]%number,i) === false)
      return;
  }
  }
  function hashLG (value) {
    return crypto.createHash(algL).update(value).digest()
  }
  function hashSM(value,nonce){
    return crypto.createHash(algS).update(value).update(nonce).digest()
  }
 
    const keyPairNew = (nonce)=> {
      nonce = nonce||crypto.randomBytes(CELL_SIZE_L);
      if(nonce.length != CELL_SIZE_L){
	throw new Error("Nonce must be "+(CELL_SIZE_L)+" size in bytes");
      }
      var shares = tss_1.splitRaw(nonce, MIN_SHARE_COUNT, HASH_COUNT);
      var PRIVATE = new Buffer(PRIVATE_KEY_BYTES);
      for(var i=0;i<shares.length;i++){
	  if(shares[i].length != CELL_SIZE_L+1){
	   throw new Error("Share must be "+(CELL_SIZE_L+1)+" size in bytes");
	}
	Buffer(shares[i]).copy(PRIVATE,i*CELL_SIZE_L,1,CELL_SIZE_L+1);
      }
      /// making public key also simular like lamport scheme
      var PUBLIC = new Buffer(PUBLIC_KEY_BYTES)
      for(var i = 0; i < HASH_COUNT; i ++) {
        hashSM(hashLG(PRIVATE.slice(i*CELL_SIZE_L, i*CELL_SIZE_L+CELL_SIZE_L)),nonce)
          .copy(PUBLIC, i*CELL_SIZE_S, 0, CELL_SIZE_S)
      }
      return {
        private: PRIVATE, public: PUBLIC
      }
    };
    
    const sign = (PRIVATE, message)=> {
      if(message.length > CELL_SIZE_L)
        throw new Error('message has incorrect size, it can have up to '+CELL_SIZE_L+" bytes")
      if(PRIVATE.length != PRIVATE_KEY_BYTES){
	throw new Error("Invalid private key length, private key must have "+PRIVATE_KEY_BYTES+" bytes");
      }
      var m = hashLG(message)
      var sig = [];
      var used = [];
      eachByte(m,HASH_COUNT, function (bit, i) {
	if(used.length>= MIN_SHARE_COUNT){
	sig.push(hashLG(PRIVATE.slice(CELL_SIZE_L*bit, CELL_SIZE_L*bit+CELL_SIZE_L)));
	}else{
	if(used.indexOf(bit) == -1){
	  used.push(bit);
	}else {
	  for(var c=0;c<HASH_COUNT;c++){
	    if(used.indexOf(c) == -1){
	      used.push(c);
	      bit = c;
	      break;
	    }
	  }
	}
        sig.push(PRIVATE.slice(CELL_SIZE_L*bit, CELL_SIZE_L*bit+CELL_SIZE_L));
	}
	  
	})
      return Buffer.concat(sig)
    };
    const verify = (PUBLIC, message, SIGNATURE)=>{
      if(message.length > CELL_SIZE_L)
        throw new Error('Message has incorrect size, it can have up to '+CELL_SIZE_L+" bytes");
      if(PUBLIC.length != PUBLIC_KEY_BYTES){
	throw new Error("Invalid public key size, public key must have "+PUBLIC_KEY_BYTES+" bytes");
      }
      if(SIGNATURE.length != SIGNATURE_BYTES){
	  throw new Error("Invalid signature size, signature must have "+SIGNATURE_BYTES+" bytes");
      }
      var sig = []
      var m = hashLG(message)
      var shares = [];
      try {
	var used = [];
	var nonce;
	eachByte(m,HASH_COUNT, function (bit, i) {
	  if(used.indexOf(bit) == -1){
	  used.push(bit);
	  }else {
	   for(var c=0;c<HASH_COUNT;c++){
	    if(used.indexOf(c) == -1){
	      used.push(c);
	      bit = c;
	      break;
	    }
	  }
	  }
	  var share = new Buffer(CELL_SIZE_L+1);
	  share[0] = bit+1;
	  SIGNATURE.copy(share,1,i*CELL_SIZE_L, (i+1)*CELL_SIZE_L);
	  shares.push(share);
	  
	  if(shares.length>=MIN_SHARE_COUNT)
	    return false;
        });
	if(shares.length<MIN_SHARE_COUNT){
	// console.log("warning min share",shares.length);
	  return false;
	}
	/// get nonce for future verification.
	try{
	nonce = tss_1.combineRaw(shares);
	}catch(e){
	  console.log(e);
	 return false; 
	}
	/// Similar to lamport verification. lamport uses bits, we use bytes, 
	/// we added extra nonce via Shamir's secret share, that enable use of much smallar 
	/// signatures and keys in comparing to Lamport signature scheme
	/// Lamport expose 50% of private key in first signature, we can expose minimal, depends of configuration
	/// WARNING: same key should not be used more the once.
	used = [];
	eachByte(m,HASH_COUNT, function (bit, i) {
	  if(used.length>= MIN_SHARE_COUNT){
	  assert.deepEqual(
            hashSM(SIGNATURE.slice(i*CELL_SIZE_L, (i+1)*CELL_SIZE_L),nonce),
            PUBLIC.slice(CELL_SIZE_S*bit, CELL_SIZE_S*bit+CELL_SIZE_S),
            'not authentic'
          )
	  }else {
	  if(used.indexOf(bit) == -1){
	  used.push(bit);
	  }else {
	    for(var c=0;c<HASH_COUNT;c++){
	    if(used.indexOf(c) == -1){
	      used.push(c);
	      bit = c;
	      break;
	    }
	  }
	  }
	  assert.deepEqual(
            hashSM(hashLG(SIGNATURE.slice(i*CELL_SIZE_L, (i+1)*CELL_SIZE_L)),nonce),
            PUBLIC.slice(CELL_SIZE_S*bit, CELL_SIZE_S*bit+CELL_SIZE_S),
            'not authentic'
          )
          
	  }
        })
	return true;
	
      } catch (err) {
        if(/not authentic/.test(err.message)) return false
        throw err
      }
    };
return {
 keyPairNew:keyPairNew,
 sign:sign,
 verify:verify
};
  
}




