# Salty-NaCl

> Salty-NaCl is NaCl encryption/ decryption implementation that you can understand. 


## Install

```
$ npm install salty-nacl
```


## Usage

```js
const salty = require('salty-nacl');

#### Generating KeyPair with Passphrase


sender = salty.generateKeyPair("Africa is the land of my birth")
receiver = salty.generateKeyPair("Love is all you need")
badguy = salty.generateKeyPair("I want to break this")

//=> { publicKey,   
// secretKey
//  }


#### Generating Random Nonce

nonce = salty.getRandomNonce()


#### Encrypt Message

message= "Africa Unite"
encryptedMessage=salty.encrypt(message,nonce,receiver.publicKey,sender.secretKey)


#### Decrypt Message

decryptMessage = salty.decrypt(encryptedMessage,nonce,sender.publicKey,receiver.secretKey)
//=> "Africa Unite"

decryptMessage = salty.decrypt(encryptedMessage,nonce,sender.publicKey,badguy.secretKey)
//=> null

```


## Related
TweetNaCl
## License

MIT © [Andrews Agyemang Opoku](http://fandrews.com)
