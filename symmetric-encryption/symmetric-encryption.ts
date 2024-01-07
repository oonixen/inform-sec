// симметричное шифрование методом aes-256

import * as fs from 'fs'
import * as crypto from 'crypto'
import * as commander from 'commander'

const cipherAlgorithm = 'aes256'
const hashAlgorithm = 'sha256'
const bufferEncodingFormat = 'base64'

launchComandLineApp()

function launchComandLineApp () {
  const program = new commander.Command()

  program
    .command('encrypt')
    .option('-m, --message <string>')
    .option('-s, --secret-key <string>')
    .action((_, {_optionValues}) => encryptAction(_optionValues.message, _optionValues.secretKey))

  program  
    .command('decrypt')
    .option('-m, --message <string>')
    .option('-s, --secret-key <string>')
    .action((_, {_optionValues}) => decryptAction(_optionValues.message, _optionValues.secretKey))

  program.parse(process.argv);
}

function encrypt (message: string, secretKey: string) {
  // хэш секретного ключа длиной 256 бит
  const hashedSecretKey = crypto.createHash(hashAlgorithm).update(secretKey)
  // псевдослучайная последовательность символов для повышения безопасности
  const iv = crypto.randomBytes(16)
  // создание шифра
  const cipher = crypto.createCipheriv(cipherAlgorithm, hashedSecretKey.digest(), iv)
  // составление зашифрованного сообщения готового к отправке
  const encryptedMessage = Buffer.concat([iv, cipher.update(Buffer.from(message)), cipher.final()])

  return encryptedMessage.toString(bufferEncodingFormat)
}

function decrypt (encryptedMessage: string, secretKey: string) {
  // хэш секретного ключа длиной 256 бит
  const sha256 = crypto.createHash(hashAlgorithm).update(secretKey)
  // двоичные данные сообщения
  const input = Buffer.from(encryptedMessage, bufferEncodingFormat)
  // отделение вектора инициализации от сообщения
  const iv = input.slice(0, 16)
  // создание объекта дешифрования
  const decipher = crypto.createDecipheriv(cipherAlgorithm, sha256.digest(), iv)
  // отделение сообщения от вектора инициализации
  const cipherText = input.slice(16)
  // дешифрование сообщения
  const dectyptedMessage = Buffer.concat([decipher.update(cipherText), decipher.final()])

  return dectyptedMessage.toString()
}

function encryptAction (message: string , secretKey: string) {
  const encryptedMessage = encrypt(message, secretKey)

  fs.writeFile('encrypted-message(symmetric-encryption).txt', encryptedMessage, err => {
    if (err) throw err
  })
  console.log(encryptedMessage)
}

function decryptAction (message: string , secretKey: string) {
  const dectyptedMessage = decrypt(message, secretKey)

  fs.writeFile('decrypted-message(symmetric-encryption).txt', dectyptedMessage, err => {
    if (err) throw err
  })
  console.log(dectyptedMessage)
}