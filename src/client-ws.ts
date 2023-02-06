import WebSocket from 'isomorphic-ws'
import {
    ADNLClient,
    ADNLClientState
} from './client'
import { ADNLPacket } from './packet'

class ADNLClientWS extends ADNLClient {
    private url: string

    constructor (url: string, peerPublicKey: Uint8Array | string) {
        super(null, url, peerPublicKey)

        this.url = url
    }

    private async parse (message: any): Promise<Buffer> {
        let data: Buffer

        switch (true) {
            case typeof message === 'string':
                data = Buffer.from(message)

                break
            case message instanceof Buffer:
                data = message
                break
            case message instanceof ArrayBuffer:
                data = Buffer.from(message)
                break
            default:
                const blob = message as unknown as Blob

                data = Buffer.from(await blob.arrayBuffer())

                break
        }

        return data
    }

    protected onHandshake (): void {
        this.socket.send(this.handshake)
    }

    public async connect (): Promise<void> {
        await this.onBeforeConnect()

        this.socket = new WebSocket(this.url)

        this.socket.onopen = () => {
            this.onConnect()
            this.onHandshake()
        }

        this.socket.onmessage = async (event: WebSocket.MessageEvent) => {
            const data = await this.parse(event.data)

            this.onData(data)
        }

        this.socket.onclose = this.onClose.bind(this)
        this.socket.onerror = this.onError.bind(this)
    }

    public end (): void {
        if (
            this.state === ADNLClientState.CLOSING
            || this.state === ADNLClientState.CLOSED
        ) {
            return undefined
        }

        this.socket.close()
    }

    public write (data: Buffer): void {
        const packet = new ADNLPacket(data)
        const encrypted = this.encrypt(packet.data)

        this.socket.send(encrypted)
    }
}

export { ADNLClientWS }
