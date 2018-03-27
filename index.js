'use strict'

const nacl = require('tweetnacl');
const stringarraybuffer = require('string-arraybuffer');
const crypto = require('crypto');
const base64_arraybuffer = require('base64-arraybuffer-converter')
var assert = require('assert');

const SALT = '0ffaa74d206930aaece223f090c88dbe6685b9e66ec49ad988d84fd7dff230d1';



exports.generateKeyPair = function generateKeyPair(passphrase)
{
    assert(typeof passphrase === 'string', 'Parameter should be a String')
    let secret = crypto.pbkdf2Sync(passphrase, SALT, 10000,16, 'sha512').toString('hex');
    var keyPair = nacl.box.keyPair.fromSecretKey(stringarraybuffer.str2ab( secret))
    var encodedKeyPair = base64KeyPairEncode(keyPair)

    return encodedKeyPair;
}


exports.getRandomNonce = function getRandomNonce()
{
    var nonce=nacl.randomBytes(nacl.secretbox.nonceLength)
    return  base64_arraybuffer.ab_2_base64(nonce)
}

exports.encrypt = function encrypt(message,nonce,receiverPublicAddress,senderPrivateKey)
{   
   var buffer_message = stringarraybuffer.str2ab(message)
   var buffer_nonce = base64_arraybuffer.base64_2_ab(nonce)
   var buffer_receiverPublicAddress = base64_arraybuffer.base64_2_ab(receiverPublicAddress)
   var buffer_senderPrivateKey = base64_arraybuffer.base64_2_ab(senderPrivateKey)

   var encrypted_message=nacl.box(buffer_message, buffer_nonce, buffer_receiverPublicAddress,buffer_senderPrivateKey);

   return base64_arraybuffer.ab_2_base64( encrypted_message)
}

exports.decrypt = function decrypt(message,nonce,senderPublicAddress,receiverPrivateKey)
{   
   var buffer_message = base64_arraybuffer.base64_2_ab(message)
   var buffer_nonce = base64_arraybuffer.base64_2_ab(nonce)
   var buffer_senderPublicAddress = base64_arraybuffer.base64_2_ab(senderPublicAddress)
   var buffer_receiverPrivateKey = base64_arraybuffer.base64_2_ab(receiverPrivateKey)
  
   var decrypted_message=nacl.box.open(buffer_message, buffer_nonce, buffer_senderPublicAddress,buffer_receiverPrivateKey);

   if(decrypted_message == null){
    return decrypted_message
}
   else if(typeof(decrypted_message) === "boolean"){
       return decrypted_message
   }
   
    return stringarraybuffer.ab2str( decrypted_message)
}




function base64KeyPairEncode(keyPair){
    keyPair.publicKey = base64_arraybuffer.ab_2_base64( keyPair.publicKey)
    keyPair.secretKey = base64_arraybuffer.ab_2_base64(keyPair.secretKey)

    return keyPair
    }

function base64KeyPairDecode(keyPair){
    keyPair.publicKey = base64_arraybuffer.base64_2_ab( keyPair.publicKey)
    keyPair.secretKey = base64_arraybuffer.base64_2_ab( keyPair.secretKey)
    
    return keyPair
    }
    

  