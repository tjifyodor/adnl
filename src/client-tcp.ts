import { ADNLClient } from './client'
import { Socket } from 'net'

class ADNLClientTCP extends ADNLClient {
    constructor (url: string, peerPublicKey: Uint8Array | string) {
        super(new Socket(), url, peerPublicKey)

        this.socket
            .on('connect', this.onConnect.bind(this))
            .on('ready', this.onHandshake.bind(this))
            .on('close', this.onClose.bind(this))
            .on('data', this.onData.bind(this))
            .on('error', this.onError.bind(this))
    }
}

export { ADNLClientTCP }
