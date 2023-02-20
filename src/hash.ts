import { sha256 as _sha256 } from '@noble/hashes/sha256'

const sha256 = (bytes: Uint8Array): Uint8Array => {
    const digest = _sha256.create()
        .update(bytes)
        .digest()

    return digest
}

export {
    sha256
}
