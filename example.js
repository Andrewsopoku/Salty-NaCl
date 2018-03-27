salty=require("./")

sender = salty.generateKeyPair("Africa is the land of my birth")
receiver = salty.generateKeyPair("Love is all you need")
badguy = salty.generateKeyPair("I want to break this")
console.log(v.publicKey)
console.log(v.secretKey)

nonce = salty.getRandomNonce()



message= "Africa Unite "
encryptedMessage=salty.encrypt(message,nonce,receiver.publicKey,sender.secretKey)

decryptMessage = salty.decrypt(encryptedMessage,nonce,sender.publicKey,receiver.secretKey)


