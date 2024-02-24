<?php

/**
 * Class SecureEncryption
 *
 * This library provides functionality for encrypting and decrypting data securely.
 *
 * @category  Security
 * @package   SecureEncryption
 * @author    Ramazan Çetinkaya
 * @license   MIT License <https://opensource.org/licenses/MIT>
 * @version   1.0.0
 * @link      https://github.com/ramazancetinkaya/encrypt-decrypt
 */
class SecureEncryption
{
    /**
     * Encrypts the given data using a strong encryption algorithm.
     *
     * @param string $data The data to be encrypted.
     * @param string $key  The encryption key.
     *
     * @return string The encrypted data.
     *
     * @throws \Exception If encryption fails.
     */
    public static function encrypt(string $data, string $key): string
    {
        // Validate input parameters
        if (empty($data) || empty($key)) {
            throw new \InvalidArgumentException("Data and key cannot be empty");
        }

        // Generate a secure random salt
        $salt = random_bytes(16);

        // Derive a key from the user's input and the random salt
        $derivedKey = hash_pbkdf2("sha256", $key, $salt, 10000, 32);

        // Use a strong encryption algorithm (e.g., AES-256-GCM)
        $iv = random_bytes(16);
        $encryptedData = openssl_encrypt($data, 'aes-256-gcm', $derivedKey, 0, $iv, $tag);

        // Combine salt, IV, encrypted data, and tag for storage
        $encryptedPackage = base64_encode($salt . $iv . $encryptedData . $tag);

        return $encryptedPackage;
    }

    /**
     * Decrypts the given encrypted data using the provided key.
     *
     * @param string $encryptedData The encrypted data.
     * @param string $key           The decryption key.
     *
     * @return string The decrypted data.
     *
     * @throws \Exception If decryption fails.
     */
    public static function decrypt(string $encryptedData, string $key): string
    {
        // Validate input parameters
        if (empty($encryptedData) || empty($key)) {
            throw new \InvalidArgumentException("Encrypted data and key cannot be empty");
        }

        // Decode the base64-encoded encrypted package
        $decodedData = base64_decode($encryptedData);

        // Extract salt, IV, encrypted data, and tag
        $salt = substr($decodedData, 0, 16);
        $iv = substr($decodedData, 16, 16);
        $encryptedData = substr($decodedData, 32, -16);
        $tag = substr($decodedData, -16);

        // Derive the key using the provided salt
        $derivedKey = hash_pbkdf2("sha256", $key, $salt, 10000, 32);

        // Use the same encryption algorithm for decryption
        $decryptedData = openssl_decrypt($encryptedData, 'aes-256-gcm', $derivedKey, 0, $iv, $tag);

        if ($decryptedData === false) {
            throw new \Exception("Decryption failed");
        }

        return $decryptedData;
    }
}

?>
