import {
    ModeOfOperation,
    Counter
} from 'aes-js'

class CipherBase {
    protected cipher: ModeOfOperation.ModeOfOperationCTR

    constructor (key: Uint8Array, iv: Uint8Array) {
        this.cipher = new ModeOfOperation.ctr(key, new Counter(iv))
    }

    public final (): Uint8Array {
        return new Uint8Array([])
    }
}

class Cipher extends CipherBase {
    constructor (key: Uint8Array, iv: Uint8Array) {
        super(key, iv)
    }

    public update (data: Uint8Array): Uint8Array {
        const result = this.cipher.encrypt(data)

        return result
    }
}

class Decipher extends Cipher {
    constructor (key: Uint8Array, iv: Uint8Array) {
        super(key, iv)
    }

    public update (data: Uint8Array): Uint8Array {
        const result = this.cipher.decrypt(data)

        return result
    }
}

const createCipheriv = (_algo: string, key: Uint8Array, iv: Uint8Array): Cipher => {
    return new Cipher(key, iv)
}

const createDecipheriv = (_algo: string, key: Uint8Array, iv: Uint8Array): Decipher => {
    return new Decipher(key, iv)
}

export {
    Cipher,
    Decipher,
    createCipheriv,
    createDecipheriv
}
