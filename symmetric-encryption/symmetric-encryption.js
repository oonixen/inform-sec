"use strict";
// симметричное шифрование методом aes-256
Object.defineProperty(exports, "__esModule", { value: true });
var fs = require("fs");
var crypto = require("crypto");
var commander = require("commander");
var cipherAlgorithm = 'aes256';
var hashAlgorithm = 'sha256';
var bufferEncoding = 'base64';
launchComandLineApp();
function launchComandLineApp() {
    var program = new commander.Command();
    program
        .command('encrypt')
        .option('-m, --message <string>')
        .option('-s, --secret-key <string>')
        .action(function (_, options) { return encryptAction(options._optionValues.message, options._optionValues.secretKey); });
    program
        .command('decrypt')
        .option('-m, --message <string>')
        .option('-s, --secret-key <string>')
        .action(function (_, options) { return decryptAction(options._optionValues.message, options._optionValues.secretKey); });
    program.parse(process.argv);
}
function encrypt(message, secretKey) {
    // хэш секретного ключа длиной 256 бит
    var hashedSecretKey = crypto.createHash(hashAlgorithm).update(secretKey);
    // псевдослучайная последовательность символов для повышения безопасности
    var iv = crypto.randomBytes(16);
    // создание шифра
    var cipher = crypto.createCipheriv(cipherAlgorithm, hashedSecretKey.digest(), iv);
    // составление зашифрованного сообщения готового к отправке
    var encryptedMessage = Buffer.concat([iv, cipher.update(Buffer.from(message)), cipher.final()]);
    return encryptedMessage.toString(bufferEncoding);
}
function decrypt(encryptedMessage, secretKey) {
    // хэш секретного ключа длиной 256 бит
    var sha256 = crypto.createHash(hashAlgorithm).update(secretKey);
    // двоичные данные сообщения
    var input = Buffer.from(encryptedMessage, bufferEncoding);
    // отделение вектора инициализации от сообщения
    var iv = input.slice(0, 16);
    // создание объекта дешифрования
    var decipher = crypto.createDecipheriv(cipherAlgorithm, sha256.digest(), iv);
    // отделение сообщения от вектора инициализации
    var cipherText = input.slice(16);
    // дешифрование сообщения
    var dectyptedMessage = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return dectyptedMessage.toString();
}
function encryptAction(message, secretKey) {
    var encryptedMessage = encrypt(message, secretKey);
    fs.writeFile('encrypted-message(symmetric-encryption).txt', encryptedMessage, function (err) {
        if (err)
            throw err;
    });
    console.log(encryptedMessage);
}
function decryptAction(message, secretKey) {
    var dectyptedMessage = decrypt(message, secretKey);
    fs.writeFile('dectypted-message(symmetric-encryption).txt', dectyptedMessage, function (err) {
        if (err)
            throw err;
    });
    console.log(dectyptedMessage);
}
