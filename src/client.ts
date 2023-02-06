import EventEmitter from 'events'
import {
    createCipheriv,
    createDecipheriv,
    Cipher,
    Decipher
} from './aes'
import {
    ADNLPacket,
    PACKET_MIN_SIZE
} from './packet'
import { ADNLAESParams } from './params'
import { ADNLAddress } from './address'
import { ADNLKeys } from './keys'

enum ADNLClientState {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED
}

interface ADNLClient {
    emit(event: 'connect'): boolean
    emit(event: 'ready'): boolean
    emit(event: 'close'): boolean
    emit(event: 'data', data: Buffer): boolean
    emit(event: 'error', error: Error): boolean

    on(event: 'connect', listener: () => void): this
    on(event: 'ready', listener: () => void): this
    on(event: 'close', listener: () => void): this
    on(event: 'data', listener: (data: Buffer) => void): this
    on(event: 'error', listener: (error: Error, close: boolean) => void): this

    once(event: 'connect', listener: () => void): this
    once(event: 'ready', listener: () => void): this
    once(event: 'close', listener: () => void): this
    once(event: 'data', listener: (data: Buffer) => void): this
    once(event: 'error', listener: (error: Error, close: boolean) => void): this
}

class ADNLClient extends EventEmitter {
    protected socket: any

    protected host: string

    protected port: number

    private buffer: Buffer

    private address: ADNLAddress

    private params: ADNLAESParams

    private keys: ADNLKeys

    private cipher: Cipher

    private decipher: Decipher

    private _state = ADNLClientState.CLOSED

    constructor (socket: any, url: string, peerPublicKey: Uint8Array | string) {
        super()

        try {
            const { hostname, port } = new URL(url)

            this.host = hostname
            this.port = parseInt(port, 10)
            this.address = new ADNLAddress(peerPublicKey)
            this.socket = socket
        } catch (err) {
            throw err
        }
    }

    protected get handshake (): Buffer {
        const key = Buffer.concat([ this.keys.shared.slice(0, 16), this.params.hash.slice(16, 32) ])
        const nonce = Buffer.concat([ this.params.hash.slice(0, 4), this.keys.shared.slice(20, 32) ])
        const cipher = createCipheriv('aes-256-ctr', key, nonce)
        const payload = Buffer.concat([ cipher.update(this.params.bytes), cipher.final() ])
        const packet = Buffer.concat([ this.address.hash, this.keys.public, this.params.hash, payload ])

        return packet
    }

    public get state (): ADNLClientState {
        return this._state
    }

    protected async onBeforeConnect (): Promise<void> {
        if (this.state !== ADNLClientState.CLOSED) {
            return undefined
        }

        const keys = new ADNLKeys(this.address.publicKey)

        await keys.generate()

        this.keys = keys
        this.params = new ADNLAESParams()
        this.cipher = createCipheriv('aes-256-ctr', this.params.txKey, this.params.txNonce)
        this.decipher = createDecipheriv('aes-256-ctr', this.params.rxKey, this.params.rxNonce)
        this.buffer = Buffer.from([])
        this._state = ADNLClientState.CONNECTING
    }

    protected onConnect () {
        this.emit('connect')
    }

    protected onReady (): void {
        this._state = ADNLClientState.OPEN
        this.emit('ready')
    }

    protected onClose (): void {
        this._state = ADNLClientState.CLOSED
        this.emit('close')
    }

    protected onData (data: Buffer): void {
        this.buffer = Buffer.concat([ this.buffer, this.decrypt(data) ])

        while (this.buffer.byteLength >= PACKET_MIN_SIZE) {
            const packet = ADNLPacket.parse(this.buffer)

            if (packet === null) {
                break
            }

            this.buffer = this.buffer.slice(packet.length, this.buffer.byteLength)

            if (this.state === ADNLClientState.CONNECTING) {
                packet.payload.length !== 0
                    ? this.onError(new Error('ADNLClient: Bad handshake.'), true)
                    : this.onReady()

                break
            }

            this.emit('data', packet.payload)
        }
    }

    protected onError (error: Error, close = false): void {
        if (close) {
            this.socket.end()
        }

        this.emit('error', error)
    }

    protected onHandshake (): void {
        this.socket.write(this.handshake)
    }

    public write (data: Buffer): void {
        const packet = new ADNLPacket(data)
        const encrypted = this.encrypt(packet.data)

        this.socket.write(encrypted)
    }

    public async connect (): Promise<void> {
        await this.onBeforeConnect()

        this.socket.connect(this.port, this.host)
    }

    public end (): void {
        if (
            this.state === ADNLClientState.CLOSING
            || this.state === ADNLClientState.CLOSED
        ) {
            return undefined
        }

        this.socket.end()
    }

    protected encrypt (data: Buffer): Buffer {
        return Buffer.concat([ this.cipher.update(data) ])
    }

    protected decrypt (data: Buffer): Buffer {
        return Buffer.concat([ this.decipher.update(data) ])
    }
}

export {
    ADNLClient,
    ADNLClientState
}
