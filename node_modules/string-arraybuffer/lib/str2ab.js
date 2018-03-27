var assert = require('assert')


exports.convertStringToArrayBufferView = function convertStringToArrayBufferView(str)
{
    assert(typeof str === 'string', 'Parameter should be a string')
    var bytes = new Uint8Array(str.length);
    for (var iii = 0; iii < str.length; iii++) 
    {
        bytes[iii] = str.charCodeAt(iii);
    }

    return bytes;
}