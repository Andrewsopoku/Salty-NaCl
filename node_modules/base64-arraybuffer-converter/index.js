"use strict"
var stringarraybuffer = require('string-arraybuffer');
var btoa = require('btoa')
var atob = require('atob')
var assert = require('assert');

exports.ab_2_base64 = function ab_2_base64(buffer)
{
    var string_val=stringarraybuffer.ab2str(buffer)
    var base64_val=btoa(string_val)

    return base64_val;

}


exports.base64_2_ab = function base64_2_ab(base64_value)
{
    var string_val = atob(base64_value)
    var buffer = stringarraybuffer.str2ab(string_val)

    return buffer;

}