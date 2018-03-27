
var assert = require('assert')


exports.convertArrayBufferViewtoString = function convertArrayBufferViewtoString(buffer)
{
    assert(buffer.constructor === Uint8Array, 'Parameter should be a ArrayBuffer')
    var str = "";
    for (var iii = 0; iii < buffer.byteLength; iii++) 
    {
        str += String.fromCharCode(buffer[iii]);
    }

    return str;
}
