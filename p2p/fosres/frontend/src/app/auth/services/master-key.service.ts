import { Injectable } from '@angular/core';
import { argon2id } from '@noble/hashes/argon2.js';

/**
 * MasterKeyService
 *
 * Implements the first step of the FOSRES authentication KDF chain:
 *
 *   Argon2ID(payload=masterPassword, salt=username) → Master Key
 *
 * Parameters sourced from:
 *   - LibSodium Interactive preset:
 *     https://libsodium.gitbook.io/doc/password_hashing/default_phf
 *   - OWASP Password Storage Cheat Sheet:
 *     https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 *   - LibSodium source header:
 *     https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_pwhash_argon2id.h
 *
 * t=2   — time cost (iterations)
 * m=65536 — memory cost (64 MiB in KiB, LibSodium INTERACTIVE preset)
 * p=1   — parallelism (hardcoded to 1 in LibSodium)
 * dkLen=32 — output length (256 bits)
 *
 * Security note:
 *   @noble/hashes Argon2ID is 5x slower than native due to lack of
 *   fast Uint64Array in JavaScript. This is a known limitation documented
 *   at https://github.com/paulmillr/noble-hashes. Use the Interactive
 *   preset (64 MiB) for browser-side calls to keep latency acceptable.
 */

/** Argon2ID parameters per LibSodium Interactive preset */
export const ARGON2ID_PARAMS = {
	t: 2,
	m: 65536,	// 64 MiB in KiB — LibSodium Interactive
	p: 1,
	dkLen: 32,
} as const;

/** Output length in bytes (256-bit master key) */
export const MASTER_KEY_LENGTH = 32;

@Injectable({
	providedIn: 'root',
})
export class MasterKeyService {

	/**
	 * master_key_gen
	 *
	 * Derives the 256-bit Master Key from the user's master password
	 * and username using Argon2ID.
	 *
	 * @param masterPassword - The user's master password (UTF-8 string)
	 * @param username        - The user's username used as salt (UTF-8 string)
	 * @returns               - 32-byte Uint8Array (Master Key)
	 *
	 * @throws {Error} if masterPassword is empty
	 * @throws {Error} if username is empty
	 */
	master_key_gen(masterPassword: string, username: string): Uint8Array {
		if (!masterPassword || masterPassword.length === 0) {
			throw new Error('master_key_gen: masterPassword must not be empty');
		}
		if (!username || username.length === 0) {
			throw new Error('master_key_gen: username must not be empty');
		}

		const encoder = new TextEncoder();
		const passwordBytes = encoder.encode(masterPassword);
		const saltBytes = encoder.encode(username);

		const masterKey: Uint8Array = argon2id(
			passwordBytes,
			saltBytes,
			{
				t: ARGON2ID_PARAMS.t,
				m: ARGON2ID_PARAMS.m,
				p: ARGON2ID_PARAMS.p,
				dkLen: ARGON2ID_PARAMS.dkLen,
			}
		);

		return masterKey;
	}
}
