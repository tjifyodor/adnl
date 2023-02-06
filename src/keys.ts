import {
    getPublicKey,
    getSharedSecret
} from '@noble/ed25519'
import { randomBytes } from 'tweetnacl'

class ADNLKeys {
    private _peer: Uint8Array

    private _public: Uint8Array

    private _shared: Uint8Array

    constructor (peerPublicKey: Uint8Array) {
        this._peer = peerPublicKey
    }

    public get public (): Uint8Array {
        return new Uint8Array(this._public)
    }

    public get shared (): Uint8Array {
        return new Uint8Array(this._shared)
    }

    public async generate () {
        const privateKey = randomBytes(32)
        const publicKey = await getPublicKey(privateKey)
        const shared = await getSharedSecret(privateKey, this._peer)

        this._public = publicKey
        this._shared = shared
    }
}

export { ADNLKeys }
