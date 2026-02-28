import { argon2id, argon2Verify } from 'hash-wasm'
import { randomBytes } from 'node:crypto'

export async function hash(password: string): Promise<string> {
    const salt = randomBytes(16)
    return await argon2id({
        password,
        salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536, // 64 MB
        hashLength: 32,
        outputType: 'encoded'
    })
}

export async function verify(encodedHash: string, password: string): Promise<boolean> {
    // `hash-wasm`'s argon2Verify handles matching the parameters (iterations, memory, etc.)
    // automatically by parsing the encoded PHC string.
    return await argon2Verify({
        password,
        hash: encodedHash
    })
}
