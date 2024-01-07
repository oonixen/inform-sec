// асимметричное шифрование методом RSA

import * as fs from 'fs'
import * as crypto from 'crypto'
import * as commander from 'commander'

const hashingAlgorithm = 'sha256'
const bufferEncodingFormat = 'base64'
const publicKeyFile = 'public-key(asymmetric-encryption).txt'
const privateKeyFile = 'private-key(asymmetric-encryption).txt'

launchComandLineApp()

function launchComandLineApp () {
  const program = new commander.Command()

  program
    .command('generate')
    .action(generateKeyPair)

  program
    .command('encrypt')
    .option('-m, --message <string>')
    .action((_, {_optionValues}) => encrypt(_optionValues.message))
  
  program
    .command('decrypt')
    .option('-m, --message <string>')
    .action((_, {_optionValues}) => decrypt(_optionValues.message))

  program.parse(process.argv);
}

function generateKeyPair () {
  // генерация пары ключей со стандартной длиной в 2048 бит
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const exportedKeyType = 'pkcs1'
  const exportedKeyFormat = 'pem'
  // экспорт публичного ключа
  const exportedPublicKeyBuffer = publicKey.export({ type: exportedKeyType, format: exportedKeyFormat })
  // экспорт приватного ключа
  const exportedPrivateKeyBuffer = privateKey.export({ type: exportedKeyType, format: exportedKeyFormat })

  // запись публичного ключа
  fs.writeFile(publicKeyFile, exportedPublicKeyBuffer, err => {
    if (err) throw err
  })

  // запись приватного ключа
  fs.writeFile(privateKeyFile, exportedPrivateKeyBuffer, err => {
    if (err) throw err
  })

  console.log(`Файлы с ключами сгенерированы`)
}

function encrypt (message: string) {

  const publicKey = fs.readFileSync(publicKeyFile, 'utf-8')

  // шифрование сообщения публичным ключом
  const encryptedDataBuffer = crypto.publicEncrypt(
    {
      key: Buffer.from(publicKey),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: hashingAlgorithm,
    },
    Buffer.from(message)
  )

  const encryptedData = encryptedDataBuffer.toString(bufferEncodingFormat)

  fs.writeFile('encrypted-message(asymmetric-encryption).txt', encryptedData, err => {
    if (err) throw err
  })

  console.log(encryptedData)
}

function decrypt (message: string) {

  const privateKey = fs.readFileSync(privateKeyFile, 'utf-8')

  // дешифрование сообщения приватным ключом
  const decryptedData = crypto.privateDecrypt(
    {
      key: Buffer.from(privateKey),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: hashingAlgorithm
    },
    Buffer.from(message, bufferEncodingFormat)
  ).toString()

  fs.writeFile('decrypted-message(asymmetric-encryption).txt', decryptedData, err => {
    if (err) throw err
  })

  console.log(decryptedData) 
}
