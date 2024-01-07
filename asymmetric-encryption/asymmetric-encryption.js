"use strict";
// асимметричное шифрование методом RSA
Object.defineProperty(exports, "__esModule", { value: true });
var fs = require("fs");
var crypto = require("crypto");
var commander = require("commander");
var hashingAlgorithm = 'sha256';
var bufferEncodingFormat = 'base64';
var publicKeyFile = 'public-key(asymmetric-encryption).txt';
var privateKeyFile = 'private-key(asymmetric-encryption).txt';
launchComandLineApp();
function launchComandLineApp() {
    var program = new commander.Command();
    program
        .command('generate')
        .action(generateKeyPair);
    program
        .command('encrypt')
        .option('-m, --message <string>')
        .action(function (_, _a) {
        var _optionValues = _a._optionValues;
        return encrypt(_optionValues.message);
    });
    program
        .command('decrypt')
        .option('-m, --message <string>')
        .action(function (_, _a) {
        var _optionValues = _a._optionValues;
        return decrypt(_optionValues.message);
    });
    program.parse(process.argv);
}
function generateKeyPair() {
    var _a = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }), publicKey = _a.publicKey, privateKey = _a.privateKey;
    var exportedKeyType = 'pkcs1';
    var exportedKeyFormat = 'pem';
    var exportedPublicKeyBuffer = publicKey.export({ type: exportedKeyType, format: exportedKeyFormat });
    var exportedPrivateKeyBuffer = privateKey.export({ type: exportedKeyType, format: exportedKeyFormat });
    fs.writeFile(publicKeyFile, exportedPublicKeyBuffer, function (err) {
        if (err)
            throw err;
    });
    fs.writeFile(privateKeyFile, exportedPrivateKeyBuffer, function (err) {
        if (err)
            throw err;
    });
    console.log("\u0424\u0430\u0439\u043B\u044B \u0441 \u043A\u043B\u044E\u0447\u0430\u043C\u0438 \u0441\u0433\u0435\u043D\u0435\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u044B");
}
function encrypt(message) {
    var publicKey = fs.readFileSync(publicKeyFile, 'utf-8');
    var encryptedDataBuffer = crypto.publicEncrypt({
        key: Buffer.from(publicKey),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: hashingAlgorithm,
    }, Buffer.from(message));
    var encryptedData = encryptedDataBuffer.toString(bufferEncodingFormat);
    fs.writeFile('encrypted-message(asymmetric-encryption).txt', encryptedData, function (err) {
        if (err)
            throw err;
    });
    console.log(encryptedData);
}
function decrypt(message) {
    var privateKey = fs.readFileSync(privateKeyFile, 'utf-8');
    var decryptedData = crypto.privateDecrypt({
        key: Buffer.from(privateKey),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: hashingAlgorithm
    }, Buffer.from(message, bufferEncodingFormat)).toString();
    fs.writeFile('decrypted-message(asymmetric-encryption).txt', decryptedData, function (err) {
        if (err)
            throw err;
    });
    console.log(decryptedData);
}
