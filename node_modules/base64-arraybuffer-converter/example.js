var base64_arraybuffer=require('./')

var uint8 = new Uint8Array ([ 73, 32, 108, 111, 118, 101, 32, 65, 102, 114, 105, 99, 97 ])
var base64_value = base64_arraybuffer.ab_2_base64(uint8)

console.log(base64_value)

arrayBuffer = base64_arraybuffer.base64_2_ab(base64_value)
console.log(arrayBuffer)