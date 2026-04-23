import crypto from 'crypto';

/**
 * Derives a 32-byte key from the ENCRYPTION_KEY environment variable.
 * Uses scryptSync for consistent key derivation.
 */
function deriveKey(): Buffer {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  
  if (!encryptionKey) {
    throw new Error('ENCRYPTION_KEY environment variable is not set');
  }

  // Use scryptSync to derive a consistent 32-byte key from the env variable
  // scryptSync(password, salt, keylen, options)
  // Using empty salt for deterministic derivation from the same ENCRYPTION_KEY
  return crypto.scryptSync(encryptionKey, '', 32);
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns a string in the format: iv_hex:authTag_hex:ciphertext_hex
 * 
 * @param text - The plaintext string to encrypt
 * @returns Encrypted string in format iv:authTag:ciphertext (all hex-encoded)
 */
export function encrypt(text: string): string {
  try {
    const key = deriveKey();
    
    // Generate a random 12-byte IV for each encryption
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt the text
    const encryptedBuffer = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final()
    ]);
    
    // Get the 16-byte authentication tag
    const authTag = cipher.getAuthTag();
    
    // Return in format: iv_hex:authTag_hex:ciphertext_hex
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encryptedBuffer.toString('hex')}`;
  } catch (error) {
    console.error('[Encryption] Error encrypting data:', error);
    throw error;
  }
}

/**
 * Decrypts a string encrypted with the encrypt() function.
 * Implements backward compatibility: if the input does not match the expected format
 * (3 colon-separated hex parts), returns the raw input unchanged.
 * 
 * @param hash - The encrypted string in format iv:authTag:ciphertext or legacy plaintext
 * @returns Decrypted plaintext string, or the original input if format is invalid
 */
export function decrypt(hash: string): string {
  try {
    // Check if the input matches the encrypted format: 3 colon-separated parts
    const parts = hash.split(':');
    
    if (parts.length !== 3) {
      // Not in encrypted format - return as-is (legacy data compatibility)
      return hash;
    }

    const [ivHex, authTagHex, ciphertextHex] = parts;

    // Validate that all parts are valid hex strings
    if (!isValidHex(ivHex) || !isValidHex(authTagHex) || !isValidHex(ciphertextHex)) {
      // Not valid hex format - return as-is
      return hash;
    }

    const key = deriveKey();
    
    // Convert hex strings back to buffers
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const ciphertext = Buffer.from(ciphertextHex, 'hex');
    
    // Validate IV length (should be 12 bytes)
    if (iv.length !== 12) {
      return hash;
    }
    
    // Validate auth tag length (should be 16 bytes)
    if (authTag.length !== 16) {
      return hash;
    }

    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    
    // Set the authentication tag
    decipher.setAuthTag(authTag);
    
    // Decrypt the ciphertext
    const decryptedBuffer = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    
    return decryptedBuffer.toString('utf8');
  } catch (error) {
    // Graceful degradation: if decryption fails, return the original input
    console.warn('[Encryption] Error decrypting data, returning original input:', error instanceof Error ? error.message : String(error));
    return hash;
  }
}

/**
 * Validates that the ENCRYPTION_KEY environment variable is set and has sufficient length.
 * Logs a warning to console if validation fails.
 */
export function validateEncryptionKey(): void {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  
  if (!encryptionKey) {
    console.warn('[Encryption] WARNING: ENCRYPTION_KEY environment variable is not set. Encryption will fail at runtime.');
    return;
  }
  
  // Warn if the key is too short (less than 16 characters is weak)
  if (encryptionKey.length < 16) {
    console.warn(`[Encryption] WARNING: ENCRYPTION_KEY is too short (${encryptionKey.length} chars). Recommended minimum is 16 characters for security.`);
  }
}

/**
 * Helper function to check if a string is valid hexadecimal.
 */
function isValidHex(str: string): boolean {
  return /^[0-9a-f]*$/.test(str);
}
