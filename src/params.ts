import { sha256 } from './hash'
import { randomBytes } from 'tweetnacl'

class ADNLAESParams {
    private _bytes: Uint8Array

    constructor () {
        this._bytes = new Uint8Array(randomBytes(160))
    }

    public get bytes (): Uint8Array {
        return new Uint8Array(this._bytes)
    }

    public get rxKey (): Uint8Array {
        return this.bytes.slice(0, 32)
    }

    public get txKey (): Uint8Array {
        return this.bytes.slice(32, 64)
    }

    public get rxNonce (): Uint8Array {
        return this.bytes.slice(64, 80)
    }

    public get txNonce (): Uint8Array {
        return this.bytes.slice(80, 96)
    }

    public get padding (): Uint8Array {
        return this.bytes.slice(96, 160)
    }

    public get hash (): Uint8Array {
        const hash = sha256(this._bytes)

        return hash
    }
}

export { ADNLAESParams }
