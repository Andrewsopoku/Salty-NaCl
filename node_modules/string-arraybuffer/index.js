

"use strict";

var str2ab = require("./lib/str2ab.js");
var ab2str = require("./lib/ab2str.js")


module.exports = {
    str2ab: str2ab.convertStringToArrayBufferView,
    ab2str: ab2str.convertArrayBufferViewtoString
}

