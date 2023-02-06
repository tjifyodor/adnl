import { bytesToHex } from './utils'
import {
    SHA256,
    SHA512,
    enc
} from 'crypto-js'

const sha256 = (bytes: Uint8Array): Uint8Array => {
    const hex = bytesToHex(bytes)
    const words = enc.Hex.parse(hex)
    const hash = SHA256(words).toString()

    return new Uint8Array(Buffer.from(hash, 'hex'))
}

const sha512 = (bytes: Uint8Array): Uint8Array => {
    const hex = bytesToHex(bytes)
    const words = enc.Hex.parse(hex)
    const hash = SHA512(words).toString()

    return new Uint8Array(Buffer.from(hash, 'hex'))
}

export {
    sha256,
    sha512
}
