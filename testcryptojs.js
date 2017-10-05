// npm install crypto-js

var CryptoJS = require("crypto-js");
var AES = require("crypto-js/aes");

var key = CryptoJS.enc.Base64.parse("Aj5MRqFpbyxvvyWK2eTu2V9FbD/iAODreM1kZMr2RuI=");

function encrypt(key, data) {
  var iv = CryptoJS.lib.WordArray.random(16);
  var encrypted = CryptoJS.AES.encrypt(data, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC
  });
  
  return CryptoJS.enc.Base64.stringify(iv) + "." + CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
}

function decrypt(key, cipher) {
  var parts = cipher.split(".");
  var plain = CryptoJS.AES.decrypt(parts[1], key, {
      iv: CryptoJS.enc.Base64.parse(parts[0]),
      mode: CryptoJS.mode.CBC
  });
  
  return plain.toString(CryptoJS.enc.Utf8);
}

var swt = "exp=636428389509689879";
console.log("swt = " + swt);

var cipher = encrypt(key, swt);
console.log("cipher = " + cipher);

var result = decrypt(key, cipher);
console.log("result = " + result);
console.log(swt == result);

