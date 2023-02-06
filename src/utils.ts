const uintToHex = (uint: number): string => {
    const hex = `0${uint.toString(16)}`

    return hex.slice(-(Math.floor(hex.length / 2) * 2))
}

const bytesToHex = (bytes: Uint8Array): string => {
    return bytes.reduce((acc, uint) => `${acc}${uintToHex(uint)}`, '')
}

export { bytesToHex }
