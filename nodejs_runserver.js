const aesjs = require("./node_modules/aes-js/index.js");
const sha256 = require("./node_modules/crypto-js/sha256.js");
const crypto_random = require("./node_modules/js-crypto-random/dist/random.js");
const express = require("./node_modules/express/index.js");
const bodyParser = require("./node_modules/body-parser/index.js");
const cryptico = require("./node_modules/cryptico/lib/cryptico.js");
const Base64 = require("./node_modules/js-base64/base64.js").Base64;


/*
*
*   Auxiliary functions for the cryptographic
*
*/


const LENGTH_OF_ELEMENT_HASHING = 2 ** 32;


function toHexFormat(mas){
    return mas.reduce((hexString, elem) => hexString + elem.toString(16), '');
}

function generateIv(){
    return Array.from(crypto_random.getRandomBytes(16));
}

function toPositiveNumbers(mas){
    return mas.map((elem) => (LENGTH_OF_ELEMENT_HASHING + elem) % LENGTH_OF_ELEMENT_HASHING);
}

function getSHA256(text){
    return toPositiveNumbers(sha256(text).words);
}

function getNormalizedKey(key){
    const key_128bit_4elements = getSHA256(key).slice(0, 4);
    const keyNormalizedHexes = toHexFormat(key_128bit_4elements).match(/.{1,2}/g) || [];
    const keyNormalized = keyNormalizedHexes.map(keyHex => parseInt(keyHex, 16));
    return keyNormalized;
}

function preparePlainText(plainText) {
    // Convert text to UTF-8 Array
    let textUint8Array = new TextEncoder().encode(plainText);
    // Create text with length is a multiple of 16 Byte (with spaces at the end)
    const rest16bytesLength = 16 - (textUint8Array.length % 16 || 16);
    const textUint8ArrayFilled = Uint8Array.from([
        ...Array.from(textUint8Array),
        ...Array.from({ length: rest16bytesLength }, () => 32), // 32 is UTF-8 code of space
    ]);
    return textUint8ArrayFilled;
}


/*
*
*   AES functions
*
*/


function encryptAES256_CBC(key, plainText, iv) {
    const textUint8ArrayFilled = preparePlainText(plainText);
    const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    const encryptedBytes = aesCbc.encrypt(textUint8ArrayFilled);
    // The binary data converted to hex
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex;
}

function decryptAES256_CBC(key, encryptedText, iv){
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
    const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
    const decryptedTextBytes = aesCbc.decrypt(encryptedBytes);
    const decryptedText = new TextDecoder().decode(decryptedTextBytes);
    return decryptedText;
}


function encryptAES256_CFB(key, plainText, iv){
    const segmentSize = 8;
    const textUint8ArrayFilled = preparePlainText(plainText);
    const aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segmentSize);
    const encryptedBytes = aesCfb.encrypt(textUint8ArrayFilled);
    // The binary data converted to hex
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex;
}

function decryptAES256_CFB(key, encryptedText, iv){
    const segmentSize = 8;
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
    const aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segmentSize);
    const decryptedTextBytes = aesCfb.decrypt(encryptedBytes);
    const decryptedText = new TextDecoder().decode(decryptedTextBytes);
    return decryptedText;
}


function encryptAES256_CTR(key, plainText){
    const textUint8ArrayFilled = preparePlainText(plainText);
    const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
    const encryptedBytes = aesCtr.encrypt(textUint8ArrayFilled);
    // The binary data converted to hex
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex;
}

function decryptAES256_CTR(key, encryptedText){
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
    const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
    const decryptedTextBytes = aesCtr.decrypt(encryptedBytes);
    const decryptedText = new TextDecoder().decode(decryptedTextBytes);
    return decryptedText;
}


function encryptAES256_ECB(key, plainText){
    const textUint8ArrayFilled = preparePlainText(plainText);
    const aesEcb = new aesjs.ModeOfOperation.ecb(key);
    const encryptedBytes = aesEcb.encrypt(textUint8ArrayFilled);
    // The binary data converted to hex
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex;
}

function decryptAES256_ECB(key, encryptedText){
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
    const aesEcb = new aesjs.ModeOfOperation.ecb(key);
    const decryptedTextBytes = aesEcb.decrypt(encryptedBytes);
    const decryptedText = new TextDecoder().decode(decryptedTextBytes);
    return decryptedText;
}


function encryptAES256_OFB(key, plainText, iv){
    const textUint8ArrayFilled = preparePlainText(plainText);
    const aesOfb = new aesjs.ModeOfOperation.ofb(key, iv);
    const encryptedBytes = aesOfb.encrypt(textUint8ArrayFilled);
    // The binary data converted to hex
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
    return encryptedHex;
}

function decryptAES256_OFB(key, encryptedText, iv){
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
    const aesOfb = new aesjs.ModeOfOperation.ofb(key, iv);
    const decryptedTextBytes = aesOfb.decrypt(encryptedBytes);
    const decryptedText = new TextDecoder().decode(decryptedTextBytes);
    return decryptedText;
}


/*
*
*   RSA functions
*
*/


function generateRSAopenKeyJSON(key_phrase, rsa_key_len){
    let rsa_pair = cryptico.generateRSAKey(key_phrase, rsa_key_len);
    let open_key_string = cryptico.publicKeyString(rsa_pair);
    let open_key_md5 = cryptico.publicKeyID(open_key_string);
    return {
        "open_rsa_key": open_key_string,
        "key_md5": open_key_md5,
    };
}

function encryptRSA(open_key, plain_text){
    plain_text = Base64.encode(plain_text);
    let encryption_result = cryptico.encrypt(plain_text, open_key);
    return {
        "encryption_result": encryption_result.cipher,
    };
}


/*
*
*   NodeJs local server for AES/RSA data encrypt/decrypt from Django requests and some other features
*   Using HTTP 3000 port for data transmission (POST)
*
*/


console.log("(INIT INFO) Crypto server start work => localhost:3000");
const app = express();
const urlencodedParser = bodyParser.urlencoded({extended: false});

app.post("/aes256ecb_encrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let encrypted_data = encryptAES256_ECB(getNormalizedKey(user_key), user_data);
    console.log(encrypted_data);
    response.send(`${encrypted_data}`);
});

app.post("/aes256ecb_decrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let decrypted_data = decryptAES256_ECB(getNormalizedKey(user_key), user_data);
    console.log(decrypted_data);
    response.send(`${decrypted_data}`);
});

app.post("/aes256cbc_encrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = generateIv();
    let encrypted_data = encryptAES256_CBC(getNormalizedKey(user_key), user_data, user_iv);
    let json_resp = {
        "encrypted_data": encrypted_data,
        "user_iv": user_iv
    };
    console.log(json_resp);
    response.send(`${JSON.stringify(json_resp)}`);
});

app.post("/aes256cbc_decrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = request.body["user_iv"];
    user_iv = user_iv.slice(1, -1);
    user_iv = user_iv.split(',').map(Number);
    let decrypted_data = decryptAES256_CBC(getNormalizedKey(user_key), user_data, user_iv);
    console.log(decrypted_data);
    response.send(`${decrypted_data}`);
});

app.post("/aes256ctr_encrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let encrypted_data = encryptAES256_CTR(getNormalizedKey(user_key), user_data);
    console.log(encrypted_data);
    response.send(`${encrypted_data}`);
});

app.post("/aes256ctr_decrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let decrypted_data = decryptAES256_CTR(getNormalizedKey(user_key), user_data);
    console.log(decrypted_data);
    response.send(`${decrypted_data}`);
});

app.post("/aes256cfb_encrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = generateIv();
    let encrypted_data = encryptAES256_CFB(getNormalizedKey(user_key), user_data, user_iv);
    let json_resp = {
        "encrypted_data": encrypted_data,
        "user_iv": user_iv
    };
    console.log(json_resp);
    response.send(`${JSON.stringify(json_resp)}`);
});

app.post("/aes256cfb_decrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = request.body["user_iv"];
    user_iv = user_iv.slice(1, -1);
    user_iv = user_iv.split(',').map(Number);
    let decrypted_data = decryptAES256_CFB(getNormalizedKey(user_key), user_data, user_iv);
    console.log(decrypted_data);
    response.send(`${decrypted_data}`);
});

app.post("/aes256ofb_encrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = generateIv();
    let encrypted_data = encryptAES256_OFB(getNormalizedKey(user_key), user_data, user_iv);
    let json_resp = {
        "encrypted_data": encrypted_data,
        "user_iv": user_iv
    };
    console.log(json_resp);
    response.send(`${JSON.stringify(json_resp)}`);
});

app.post("/aes256ofb_decrypt", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let user_data = request.body["user_data"];
    let user_iv = request.body["user_iv"];
    user_iv = user_iv.slice(1, -1);
    user_iv = user_iv.split(',').map(Number);
    let decrypted_data = decryptAES256_OFB(getNormalizedKey(user_key), user_data, user_iv);
    console.log(decrypted_data);
    response.send(`${decrypted_data}`);
});

app.post("/sha256_numerical_value", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let user_key = request.body["user_key"];
    let sha256_numerical_value = getSHA256(user_key)[0];
    console.log(sha256_numerical_value);
    response.send(`${sha256_numerical_value}`);
});

app.post("/rsa_generate_open_key", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let key_phrase = request.body["key_phrase"];
    let key_len = request.body["key_len"];
    let generated_result = generateRSAopenKeyJSON(key_phrase, key_len);
    console.log(generated_result);
    response.send(`${JSON.stringify(generated_result)}`);
});

app.post("/rsa_encryption", urlencodedParser, function (request, response) {
    if(!request.body) return response.sendStatus(400);
    console.log(request.body);
    let open_rsa_key = request.body["open_rsa_key"];
    let key_md5 = request.body["key_md5"];
    let data = request.body["data"];
    if (key_md5 !== cryptico.publicKeyID(open_rsa_key)){
        let encryption_result = {
            "encrypted_data": "ERROR: the open key was damaged!"
        };
        console.log(encryption_result);
        response.send(`${JSON.stringify(encryption_result)}`);
    }

    let encryption_result = encryptRSA(open_rsa_key, data);
    console.log(encryption_result);
    response.send(`${JSON.stringify(encryption_result)}`);
});

app.listen(3000);
