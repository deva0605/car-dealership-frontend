import { describe, expect, it, beforeEach } from 'vitest';
import { encrypt, decrypt, validateEncryptionKey } from './utils/encryption';

describe('Encryption Utility', () => {
  beforeEach(() => {
    // Ensure ENCRYPTION_KEY is set for tests
    if (!process.env.ENCRYPTION_KEY) {
      process.env.ENCRYPTION_KEY = 'test-encryption-key-for-unit-tests-minimum-16-chars';
    }
  });

  describe('encrypt function', () => {
    it('should encrypt a plaintext string and return a colon-separated format', () => {
      const plaintext = 'John Doe';
      const encrypted = encrypt(plaintext);

      // Verify format: iv_hex:authTag_hex:ciphertext_hex
      const parts = encrypted.split(':');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toMatch(/^[0-9a-f]+$/); // IV in hex
      expect(parts[1]).toMatch(/^[0-9a-f]+$/); // Auth tag in hex
      expect(parts[2]).toMatch(/^[0-9a-f]+$/); // Ciphertext in hex
    });

    it('should produce different ciphertexts for the same plaintext (random IV)', () => {
      const plaintext = 'customer@example.com';
      const encrypted1 = encrypt(plaintext);
      const encrypted2 = encrypt(plaintext);

      // Different IVs should produce different ciphertexts
      expect(encrypted1).not.toBe(encrypted2);

      // But both should decrypt to the same plaintext
      expect(decrypt(encrypted1)).toBe(plaintext);
      expect(decrypt(encrypted2)).toBe(plaintext);
    });

    it('should encrypt special characters correctly', () => {
      const plaintext = 'Jane@123!#$%^&*()';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt unicode characters correctly', () => {
      const plaintext = '张三 李四 مرحبا Привет';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt long strings (200+ characters)', () => {
      const plaintext = 'a'.repeat(250);
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('decrypt function', () => {
    it('should decrypt an encrypted string back to plaintext', () => {
      const plaintext = 'Customer Name';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should return plaintext unchanged if input does not match encrypted format', () => {
      const plaintext = 'legacy-unencrypted-data';
      const decrypted = decrypt(plaintext);

      expect(decrypted).toBe(plaintext);
    });

    it('should return input unchanged if format has wrong number of colons', () => {
      const malformed = 'abc:def'; // Only 2 parts, not 3
      const decrypted = decrypt(malformed);

      expect(decrypted).toBe(malformed);
    });

    it('should return input unchanged if hex parts are invalid', () => {
      const malformed = 'xyz:abc:def'; // Not valid hex
      const decrypted = decrypt(malformed);

      expect(decrypted).toBe(malformed);
    });

    it('should gracefully handle decryption errors and return original input', () => {
      // Create a valid-looking but corrupted encrypted string
      const corrupted = 'a'.repeat(24) + ':' + 'b'.repeat(32) + ':' + 'c'.repeat(32);
      const decrypted = decrypt(corrupted);

      // Should return the corrupted string unchanged
      expect(decrypted).toBe(corrupted);
    });

    it('should handle empty string encryption/decryption', () => {
      const plaintext = '';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('Round-trip encryption/decryption', () => {
    it('should encrypt and decrypt customer name correctly', () => {
      const customerName = 'John Doe';
      const encrypted = encrypt(customerName);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(customerName);
    });

    it('should encrypt and decrypt customer contact correctly', () => {
      const customerContact = 'john.doe@example.com';
      const encrypted = encrypt(customerContact);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(customerContact);
    });

    it('should encrypt and decrypt customer ID correctly', () => {
      const customerId = 'CUST-12345-ABC';
      const encrypted = encrypt(customerId);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(customerId);
    });

    it('should handle multiple independent field encryptions', () => {
      const fields = {
        customerName: 'Alice Smith',
        customerContact: '+1-555-0123',
        customerId: 'ID-98765-XYZ',
      };

      const encrypted = {
        customerName: encrypt(fields.customerName),
        customerContact: encrypt(fields.customerContact),
        customerId: encrypt(fields.customerId),
      };

      const decrypted = {
        customerName: decrypt(encrypted.customerName),
        customerContact: decrypt(encrypted.customerContact),
        customerId: decrypt(encrypted.customerId),
      };

      expect(decrypted).toEqual(fields);
    });
  });

  describe('Backward compatibility', () => {
    it('should pass through legacy unencrypted data without modification', () => {
      const legacyData = [
        'plain-text-name',
        'email@example.com',
        'customer-id-123',
        'John Doe',
      ];

      legacyData.forEach(data => {
        const decrypted = decrypt(data);
        expect(decrypted).toBe(data);
      });
    });

    it('should handle mixed encrypted and unencrypted data in a list', () => {
      const plaintext1 = 'Customer One';
      const plaintext2 = 'Customer Two';

      const encrypted1 = encrypt(plaintext1);
      const unencrypted2 = plaintext2; // Not encrypted

      const decrypted1 = decrypt(encrypted1);
      const decrypted2 = decrypt(unencrypted2);

      expect(decrypted1).toBe(plaintext1);
      expect(decrypted2).toBe(plaintext2);
    });
  });

  describe('validateEncryptionKey function', () => {
    it('should not throw an error when ENCRYPTION_KEY is set', () => {
      process.env.ENCRYPTION_KEY = 'valid-key-for-testing';
      expect(() => validateEncryptionKey()).not.toThrow();
    });

    it('should log a warning when ENCRYPTION_KEY is not set', () => {
      const originalKey = process.env.ENCRYPTION_KEY;
      delete process.env.ENCRYPTION_KEY;

      const consoleSpy = console.warn;
      let warningLogged = false;

      console.warn = (...args: any[]) => {
        if (args[0]?.includes('ENCRYPTION_KEY')) {
          warningLogged = true;
        }
      };

      validateEncryptionKey();
      expect(warningLogged).toBe(true);

      console.warn = consoleSpy;
      process.env.ENCRYPTION_KEY = originalKey;
    });

    it('should log a warning when ENCRYPTION_KEY is too short', () => {
      const originalKey = process.env.ENCRYPTION_KEY;
      process.env.ENCRYPTION_KEY = 'short';

      const consoleSpy = console.warn;
      let warningLogged = false;

      console.warn = (...args: any[]) => {
        if (args[0]?.includes('too short')) {
          warningLogged = true;
        }
      };

      validateEncryptionKey();
      expect(warningLogged).toBe(true);

      console.warn = consoleSpy;
      process.env.ENCRYPTION_KEY = originalKey;
    });
  });

  describe('IV uniqueness', () => {
    it('should generate unique IVs for multiple encryptions of the same plaintext', () => {
      const plaintext = 'test-data';
      const encryptedValues = Array.from({ length: 10 }, () => encrypt(plaintext));

      // Extract IVs from encrypted values
      const ivs = encryptedValues.map(encrypted => encrypted.split(':')[0]);

      // All IVs should be unique
      const uniqueIvs = new Set(ivs);
      expect(uniqueIvs.size).toBe(10);
    });
  });

  describe('Format validation', () => {
    it('should verify encrypted output has exactly 3 colon-separated hex parts', () => {
      const plaintext = 'format-test';
      const encrypted = encrypt(plaintext);

      const parts = encrypted.split(':');
      expect(parts).toHaveLength(3);

      // IV should be 24 hex chars (12 bytes)
      expect(parts[0]).toHaveLength(24);

      // Auth tag should be 32 hex chars (16 bytes)
      expect(parts[1]).toHaveLength(32);

      // Ciphertext should be present
      expect(parts[2].length).toBeGreaterThan(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle whitespace-only strings', () => {
      const plaintext = '   ';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle strings with newlines and tabs', () => {
      const plaintext = 'line1\nline2\ttab';
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle very long strings (1000+ characters)', () => {
      const plaintext = 'x'.repeat(1000);
      const encrypted = encrypt(plaintext);
      const decrypted = decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });
  });
});
