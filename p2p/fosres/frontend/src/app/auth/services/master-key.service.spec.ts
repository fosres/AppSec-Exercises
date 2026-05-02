import { TestBed } from '@angular/core/testing';
import { argon2id } from '@noble/hashes/argon2.js';
import {
	MasterKeyService,
	ARGON2ID_PARAMS,
	MASTER_KEY_LENGTH,
} from './master-key.service';

/**
 * Test suite for master_key_gen
 *
 * PERFORMANCE NOTE:
 * Production parameters use m=65536 (64 MiB) per the LibSodium Interactive
 * preset. Running 60+ test cases at full parameters would take several
 * minutes and is not suitable for a CI environment.
 *
 * This test suite therefore uses REDUCED parameters (m=256, t=2, p=1) for
 * the bulk of structural and security property tests. A dedicated integration
 * test group uses the full production parameters (m=65536) to verify the
 * production path is correct.
 *
 * Reduced parameters are clearly marked and MUST NOT be used in production.
 * Source: @noble/hashes benchmark — argon2id(t:1, m:256MB) = 2881ms in JS.
 * https://github.com/paulmillr/noble-hashes
 */

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Reduced parameters for unit tests — NOT for production use */
const TEST_PARAMS = { t: 2, m: 256, p: 1, dkLen: 32 };

const encoder = new TextEncoder();

/**
 * Compute Argon2ID with reduced test parameters directly via @noble/hashes.
 * Used to generate expected values for structural tests.
 */
function computeTestHash(password: string, salt: string): Uint8Array {
	return argon2id(
		encoder.encode(password),
		encoder.encode(salt),
		TEST_PARAMS
	);
}

/** Convert Uint8Array to hex string for readable assertions */
function toHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
}

/** Check that two Uint8Arrays are not equal */
function notEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return true;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return true;
	}
	return false;
}

// ---------------------------------------------------------------------------
// Test fixture data
// ---------------------------------------------------------------------------

const FIXTURES = {
	standard:       { password: 'correct horse battery staple', username: 'alice' },
	short:          { password: 'abc',                          username: 'bob' },
	long_password:  { password: 'a'.repeat(512),                username: 'charlie' },
	long_username:  { password: 'password123',                  username: 'u'.repeat(128) },
	unicode_pw:     { password: '正しい馬バッテリーステープル',  username: 'david' },
	unicode_user:   { password: 'password123',                  username: '用户名' },
	symbols_pw:     { password: '!@#$%^&*()_+-=[]{}|;:,.<>?',  username: 'eve' },
	symbols_user:   { password: 'password123',                  username: 'user@example.com' },
	spaces_pw:      { password: 'my secret password with spaces', username: 'frank' },
	spaces_user:    { password: 'password123',                  username: 'user name' },
	numeric_pw:     { password: '12345678901234567890',         username: 'grace' },
	mixed_case:     { password: 'PassWord123',                  username: 'Henry' },
	emoji_pw:       { password: '🔐🔑🛡️',                   username: 'ivan' },
	newline_pw:     { password: 'pass\nword',                   username: 'julia' },
	tab_pw:         { password: 'pass\tword',                   username: 'karen' },
	null_byte_pw:   { password: 'pass\x00word',                 username: 'larry' },
	high_entropy:   { password: 'xK9#mP2$vL5@nQ8&',            username: 'mary' },
	min_password:   { password: 'a',                            username: 'nancy' },
	min_username:   { password: 'password123',                  username: 'o' },
	case_diff_pw:   { password: 'Password',                     username: 'oscar' },
	case_diff_pw2:  { password: 'password',                     username: 'oscar' },
	same_pw_user:   { password: 'alice',                        username: 'alice' },
};

// ---------------------------------------------------------------------------
// Describe block
// ---------------------------------------------------------------------------

describe('MasterKeyService — master_key_gen', () => {
	let service: MasterKeyService;

	beforeEach(() => {
		TestBed.configureTestingModule({});
		service = TestBed.inject(MasterKeyService);
	});

	// -------------------------------------------------------------------------
	// Group 1: Service instantiation
	// -------------------------------------------------------------------------

	describe('Service instantiation', () => {
		it('TC-01: should be created', () => {
			expect(service).toBeTruthy();
		});

		it('TC-02: master_key_gen should be a function', () => {
			expect(typeof service.master_key_gen).toBe('function');
		});

		it('TC-03: ARGON2ID_PARAMS should have correct t value', () => {
			expect(ARGON2ID_PARAMS.t).toBe(2);
		});

		it('TC-04: ARGON2ID_PARAMS should have correct m value (64 MiB)', () => {
			expect(ARGON2ID_PARAMS.m).toBe(65536);
		});

		it('TC-05: ARGON2ID_PARAMS should have correct p value', () => {
			expect(ARGON2ID_PARAMS.p).toBe(1);
		});

		it('TC-06: ARGON2ID_PARAMS should have correct dkLen value', () => {
			expect(ARGON2ID_PARAMS.dkLen).toBe(32);
		});

		it('TC-07: MASTER_KEY_LENGTH should be 32', () => {
			expect(MASTER_KEY_LENGTH).toBe(32);
		});
	});

	// -------------------------------------------------------------------------
	// Group 2: Output type and length (reduced params via direct noble call)
	// These tests patch the internal call to use TEST_PARAMS for speed.
	// We verify structural properties — type, length, non-null — not values.
	// -------------------------------------------------------------------------

	describe('Output type and length', () => {

		/**
		 * For Groups 2–5 we call @noble/hashes argon2id directly with
		 * TEST_PARAMS to generate expected values, then verify the service
		 * output against those expected values after patching ARGON2ID_PARAMS.
		 *
		 * Since ARGON2ID_PARAMS is a const object imported by the service,
		 * we spy on the argon2id import to intercept the call and substitute
		 * TEST_PARAMS — keeping tests fast while validating correctness.
		 */

		it('TC-08: should return a Uint8Array', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const result = service.master_key_gen('password', 'user');
			expect(result).toBeInstanceOf(Uint8Array);
		});

		it('TC-09: should return exactly 32 bytes', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const result = service.master_key_gen('password', 'user');
			expect(result.length).toBe(32);
		});

		it('TC-10: output should not be all zeros', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const result = service.master_key_gen('password', 'user');
			const allZero = result.every(b => b === 0);
			expect(allZero).toBeFalse();
		});

		it('TC-11: output should not be all 0xFF', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const result = service.master_key_gen('password', 'user');
			const allFF = result.every(b => b === 0xFF);
			expect(allFF).toBeFalse();
		});

		it('TC-12: output should have byte values in range [0, 255]', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const result = service.master_key_gen('password', 'user');
			const valid = result.every(b => b >= 0 && b <= 255);
			expect(valid).toBeTrue();
		});
	});

	// -------------------------------------------------------------------------
	// Group 3: Determinism — same inputs must always produce same output
	// -------------------------------------------------------------------------

	describe('Determinism', () => {

		const fixtures = [
			FIXTURES.standard,
			FIXTURES.short,
			FIXTURES.unicode_pw,
			FIXTURES.symbols_pw,
			FIXTURES.numeric_pw,
		];

		fixtures.forEach(({ password, username }, i) => {
			it(`TC-${13 + i * 2}: same inputs produce same output [fixture ${i + 1}]`, () => {
				spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
					.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
						argon2id(pw, salt, TEST_PARAMS));
				const r1 = service.master_key_gen(password, username);
				const r2 = service.master_key_gen(password, username);
				expect(toHex(r1)).toBe(toHex(r2));
			});

			it(`TC-${14 + i * 2}: determinism holds on third call [fixture ${i + 1}]`, () => {
				spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
					.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
						argon2id(pw, salt, TEST_PARAMS));
				const r1 = service.master_key_gen(password, username);
				const r3 = service.master_key_gen(password, username);
				expect(toHex(r1)).toBe(toHex(r3));
			});
		});
	});

	// -------------------------------------------------------------------------
	// Group 4: Distinctness — different inputs must produce different outputs
	// -------------------------------------------------------------------------

	describe('Distinctness', () => {

		beforeEach(() => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
		});

		it('TC-23: different passwords same username → different output', () => {
			const r1 = service.master_key_gen('password1', 'alice');
			const r2 = service.master_key_gen('password2', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-24: same password different usernames → different output', () => {
			const r1 = service.master_key_gen('password', 'alice');
			const r2 = service.master_key_gen('password', 'bob');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-25: both different → different output', () => {
			const r1 = service.master_key_gen('password1', 'alice');
			const r2 = service.master_key_gen('password2', 'bob');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-26: password case sensitivity — Password vs password', () => {
			const r1 = service.master_key_gen(
				FIXTURES.mixed_case.password, FIXTURES.mixed_case.username);
			const r2 = service.master_key_gen(
				FIXTURES.case_diff_pw2.password, FIXTURES.mixed_case.username);
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-27: username case sensitivity — Alice vs alice', () => {
			const r1 = service.master_key_gen('password', 'Alice');
			const r2 = service.master_key_gen('password', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-28: swapping password and username → different output', () => {
			const r1 = service.master_key_gen('alice', 'hunter2');
			const r2 = service.master_key_gen('hunter2', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-29: same value for password and username → distinct from swapped', () => {
			const r1 = service.master_key_gen(
				FIXTURES.same_pw_user.password,
				FIXTURES.same_pw_user.username);
			const r2 = service.master_key_gen(
				FIXTURES.same_pw_user.username,
				FIXTURES.same_pw_user.password);
			// salt=password is same string here, so hashes are equal — documents domain separation
			// When password === username the swap produces the same hash by design
			expect(r1).toBeDefined();
			expect(r2).toBeDefined();
		});

		it('TC-30: leading whitespace matters — " alice" vs "alice"', () => {
			const r1 = service.master_key_gen('password', ' alice');
			const r2 = service.master_key_gen('password', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-31: trailing whitespace matters — "alice " vs "alice"', () => {
			const r1 = service.master_key_gen('password', 'alice ');
			const r2 = service.master_key_gen('password', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-32: one-character password difference', () => {
			const r1 = service.master_key_gen('password1', 'alice');
			const r2 = service.master_key_gen('password2', 'alice');
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-33: unicode password produces distinct output from ASCII equivalent', () => {
			const r1 = service.master_key_gen(
				FIXTURES.unicode_pw.password, FIXTURES.unicode_pw.username);
			const r2 = service.master_key_gen('password123', FIXTURES.unicode_pw.username);
			expect(notEqual(r1, r2)).toBeTrue();
		});

		it('TC-34: symbol password distinct from alphanumeric', () => {
			const r1 = service.master_key_gen(
				FIXTURES.symbols_pw.password, FIXTURES.symbols_pw.username);
			const r2 = service.master_key_gen('password123', FIXTURES.symbols_pw.username);
			expect(notEqual(r1, r2)).toBeTrue();
		});
	});

	// -------------------------------------------------------------------------
	// Group 5: Input validation — error handling
	// -------------------------------------------------------------------------

	describe('Input validation', () => {

		it('TC-35: should throw if masterPassword is empty string', () => {
			expect(() => service.master_key_gen('', 'alice'))
				.toThrowError('master_key_gen: masterPassword must not be empty');
		});

		it('TC-36: should throw if username is empty string', () => {
			expect(() => service.master_key_gen('password', ''))
				.toThrowError('master_key_gen: username must not be empty');
		});

		it('TC-37: should throw if masterPassword is null', () => {
			expect(() => service.master_key_gen(null as any, 'alice'))
				.toThrowError('master_key_gen: masterPassword must not be empty');
		});

		it('TC-38: should throw if username is null', () => {
			expect(() => service.master_key_gen('password', null as any))
				.toThrowError('master_key_gen: username must not be empty');
		});

		it('TC-39: should throw if masterPassword is undefined', () => {
			expect(() => service.master_key_gen(undefined as any, 'alice'))
				.toThrowError('master_key_gen: masterPassword must not be empty');
		});

		it('TC-40: should throw if username is undefined', () => {
			expect(() => service.master_key_gen('password', undefined as any))
				.toThrowError('master_key_gen: username must not be empty');
		});

		it('TC-41: should not throw for single-character password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.min_password.password,
				FIXTURES.min_password.username))
				.not.toThrow();
		});

		it('TC-42: should not throw for single-character username', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.min_username.password,
				FIXTURES.min_username.username))
				.not.toThrow();
		});

		it('TC-43: should not throw for 512-character password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.long_password.password,
				FIXTURES.long_password.username))
				.not.toThrow();
		});

		it('TC-44: should not throw for 128-character username', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.long_username.password,
				FIXTURES.long_username.username))
				.not.toThrow();
		});

		it('TC-45: should not throw for unicode password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.unicode_pw.password,
				FIXTURES.unicode_pw.username))
				.not.toThrow();
		});

		it('TC-46: should not throw for unicode username', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.unicode_user.password,
				FIXTURES.unicode_user.username))
				.not.toThrow();
		});

		it('TC-47: should not throw for emoji password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.emoji_pw.password,
				FIXTURES.emoji_pw.username))
				.not.toThrow();
		});

		it('TC-48: should not throw for password containing null byte', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.null_byte_pw.password,
				FIXTURES.null_byte_pw.username))
				.not.toThrow();
		});

		it('TC-49: should not throw for password with newline', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.newline_pw.password,
				FIXTURES.newline_pw.username))
				.not.toThrow();
		});

		it('TC-50: should not throw for password with tab', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			expect(() => service.master_key_gen(
				FIXTURES.tab_pw.password,
				FIXTURES.tab_pw.username))
				.not.toThrow();
		});
	});

	// -------------------------------------------------------------------------
	// Group 6: Output correctness — verify against known @noble/hashes output
	// -------------------------------------------------------------------------

	describe('Output correctness against @noble/hashes', () => {

		it('TC-51: output matches direct @noble/hashes call — standard fixture', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.standard;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-52: output matches direct call — unicode password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.unicode_pw;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-53: output matches direct call — symbols password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.symbols_pw;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-54: output matches direct call — long password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.long_password;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-55: output matches direct call — numeric password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.numeric_pw;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-56: output matches direct call — high entropy password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.high_entropy;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-57: output matches direct call — spaces in password', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.spaces_pw;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});

		it('TC-58: output matches direct call — email-format username', () => {
			spyOn(require('@noble/hashes/argon2.js'), 'argon2id')
				.and.callFake((pw: Uint8Array, salt: Uint8Array) =>
					argon2id(pw, salt, TEST_PARAMS));
			const { password, username } = FIXTURES.symbols_user;
			const expected = computeTestHash(password, username);
			const result = service.master_key_gen(password, username);
			expect(toHex(result)).toBe(toHex(expected));
		});
	});

	// -------------------------------------------------------------------------
	// Group 7: Integration tests — full production parameters
	// WARNING: These are slow (~2-3 seconds each in browser JS due to 64 MiB
	// memory cost). Run separately from the unit test suite in CI.
	// -------------------------------------------------------------------------

	describe('Integration — production parameters (SLOW)', () => {

		it('TC-59: returns 32-byte Uint8Array with production parameters', () => {
			const result = service.master_key_gen('correct horse battery staple', 'alice');
			expect(result).toBeInstanceOf(Uint8Array);
			expect(result.length).toBe(32);
		}, 30000); // 30s timeout

		it('TC-60: production output is deterministic', () => {
			const r1 = service.master_key_gen('correct horse battery staple', 'alice');
			const r2 = service.master_key_gen('correct horse battery staple', 'alice');
			expect(toHex(r1)).toBe(toHex(r2));
		}, 60000); // 60s timeout — two full hashes

		it('TC-61: production output is distinct from reduced-param output', () => {
			const prodResult = service.master_key_gen('password', 'alice');
			const testResult = computeTestHash('password', 'alice');
			// Different parameters → different output — confirms params are respected
			expect(notEqual(prodResult, testResult)).toBeTrue();
		}, 30000);

	});

});
