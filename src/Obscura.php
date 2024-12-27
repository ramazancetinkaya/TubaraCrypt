<?php

/**
 * Obscura - AES Cryptor (Without GMP)
 *
 * A multi-round polynomial-based custom encryption layer on top of AES-256-CBC
 * encryption. Uses the Extended Euclidean Algorithm (instead of GMP) to compute
 * modular inverses. Optionally supports URL-safe Base64 encoding.
 *
 * @category  Cryptography
 * @package   Obscura
 * @author    Ramazan Çetinkaya
 * @license   https://opensource.org/licenses/MIT MIT License
 * @version   1.0.0
 * @link      https://github.com/ramazancetinkaya/ObscuraCrypt
 */

declare(strict_types=1);

namespace ramazancetinkaya;

use RuntimeException;

/**
 * Class ObscuraException
 *
 * Custom exception class for encryption/decryption errors.
 */
class ObscuraException extends RuntimeException
{
}

/**
 * Class Obscura
 *
 * Provides AES encryption and decryption with a multi-round polynomial-based
 * custom encryption layer for extra security. Uses an internal Extended
 * Euclidean Algorithm for modular arithmetic, so it does not require the
 * GMP extension. Also supports optional URL-safe base64 encoding.
 */
class Obscura
{
    /**
     * @var string $secretKey The secret key used for AES encryption.
     */
    private string $secretKey;

    /**
     * @var string $cipherMethod The OpenSSL cipher method to be used for AES encryption.
     */
    private string $cipherMethod;

    /**
     * @var int $ivLength The required initialization vector length for the chosen cipher method.
     */
    private int $ivLength;

    /**
     * @var bool $useUrlSafeBase64 If true, encrypt/decrypt will use URL-safe base64.
     */
    private bool $useUrlSafeBase64;

    /**
     * @var int $prime Modulus used in the multi-round custom encryption layer.
     */
    private int $prime = 257;

    /**
     * @var array<int, array{a: int, b: int}> $rounds
     * Each round is defined by an associative array with 'a' and 'b' coefficients.
     * We apply multiple passes in encryption, and reverse them in decryption.
     */
    private array $rounds = [
        ['a' => 5,  'b' => 11],  // Round 1
        ['a' => 13, 'b' => 19],  // Round 2
        ['a' => 17, 'b' => 23],  // Round 3
        ['a' => 29, 'b' => 31],  // Round 4
    ];

    /**
     * Constructor
     *
     * @param string $secretKey        The secret key for AES encryption
     * @param string $cipherMethod     The OpenSSL cipher method (e.g., 'aes-256-cbc')
     * @param bool   $useUrlSafeBase64 Toggle for URL-safe base64 (default: false)
     *
     * @throws ObscuraException If the provided cipher method is invalid or not supported.
     */
    public function __construct(
        string $secretKey,
        string $cipherMethod = 'aes-256-cbc',
        bool $useUrlSafeBase64 = false
    ) {
        // Validate cipher method
        if (!in_array($cipherMethod, openssl_get_cipher_methods(), true)) {
            throw new ObscuraException('Invalid or unsupported cipher method provided.');
        }

        // Initialize properties
        $this->secretKey        = $secretKey;
        $this->cipherMethod     = $cipherMethod;
        $this->useUrlSafeBase64 = $useUrlSafeBase64;
        $this->ivLength         = openssl_cipher_iv_length($this->cipherMethod);

        if ($this->ivLength === false) {
            throw new ObscuraException('Failed to get IV length for the specified cipher method.');
        }

        // Basic validation for the chosen prime
        if ($this->prime <= 1) {
            throw new ObscuraException('Prime must be greater than 1.');
        }

        // Check if all 'a' coefficients are invertible mod prime (via gcd check)
        foreach ($this->rounds as $round) {
            // Basic GCD approach without GMP
            $gcd = $this->basicGcd($round['a'], $this->prime);
            if ($gcd !== 1) {
                throw new ObscuraException(sprintf(
                    "Coefficient a=%d is not invertible mod %d. Make sure gcd(a, prime) = 1.",
                    $round['a'],
                    $this->prime
                ));
            }
        }
    }

    /**
     * Encrypt
     *
     * @param string $plainText The plaintext to be encrypted.
     *
     * @return string Encrypted string (base64 or URL-safe base64).
     *
     * @throws ObscuraException If encryption fails at any stage.
     */
    public function encrypt(string $plainText): string
    {
        try {
            // 1. Multi-round custom encryption
            $customEncrypted = $this->customEncrypt($plainText);

            // 2. AES encryption
            $iv        = random_bytes($this->ivLength);
            $rawCipher = openssl_encrypt(
                $customEncrypted,
                $this->cipherMethod,
                $this->adjustKeyLength($this->secretKey),
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($rawCipher === false) {
                throw new ObscuraException('AES encryption failed.');
            }

            // 3. Combine IV with cipher text
            $combined = $iv . $rawCipher;

            // 4. Encode (normal base64 or URL-safe base64)
            $encoded = base64_encode($combined);
            if ($this->useUrlSafeBase64) {
                // Make it URL-safe by replacing +, /, = with -, _, '' respectively
                $encoded = str_replace(['+', '/', '='], ['-', '_', ''], $encoded);
            }

            return $encoded;
        } catch (\Throwable $e) {
            throw new ObscuraException('Encryption process failed: ' . $e->getMessage());
        }
    }

    /**
     * Decrypt
     *
     * @param string $cipherText The ciphertext to be decrypted (base64 or URL-safe base64).
     *
     * @return string Decrypted plain text.
     *
     * @throws ObscuraException If decryption fails at any stage.
     */
    public function decrypt(string $cipherText): string
    {
        try {
            // 1. Convert from URL-safe to normal base64 if needed
            if ($this->useUrlSafeBase64) {
                $cipherText = str_replace(['-', '_'], ['+', '/'], $cipherText);
                // Attempt to restore '=' padding
                $padding = 4 - (strlen($cipherText) % 4);
                if ($padding < 4) {
                    $cipherText .= str_repeat('=', $padding);
                }
            }

            // 2. Base64 decode
            $decodedCipher = base64_decode($cipherText, true);
            if ($decodedCipher === false) {
                throw new ObscuraException('Base64 decoding of cipher text failed.');
            }

            // 3. Extract IV and raw cipher text
            $iv        = mb_substr($decodedCipher, 0, $this->ivLength, '8bit');
            $rawCipher = mb_substr($decodedCipher, $this->ivLength, null, '8bit');

            if (strlen($iv) !== $this->ivLength) {
                throw new ObscuraException('Invalid IV length. Possible corruption or manipulation.');
            }

            // 4. AES decryption
            $decrypted = openssl_decrypt(
                $rawCipher,
                $this->cipherMethod,
                $this->adjustKeyLength($this->secretKey),
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($decrypted === false) {
                throw new ObscuraException('AES decryption failed.');
            }

            // 5. Multi-round custom decryption
            $plainText = $this->customDecrypt($decrypted);

            return $plainText;
        } catch (\Throwable $e) {
            throw new ObscuraException('Decryption process failed: ' . $e->getMessage());
        }
    }

    /**
     * customEncrypt
     *
     * Applies multiple polynomial transformations in sequence to each character:
     *   Round i: x -> (a_i*x + b_i) mod prime
     *
     * @param string $plainText The original plaintext.
     *
     * @return string The transformed string after all rounds.
     */
    private function customEncrypt(string $plainText): string
    {
        $chars = mb_str_split($plainText, 1, '8bit');

        $transformed = array_map(function ($char) {
            $x = ord($char);
            // Apply each round in sequence
            foreach ($this->rounds as $round) {
                $x = ($round['a'] * $x + $round['b']) % $this->prime;
            }
            return chr($x);
        }, $chars);

        return implode('', $transformed);
    }

    /**
     * customDecrypt
     *
     * Reverses the multiple polynomial transformations in reverse order:
     *   Round i: x -> ( (x - b_i) * a_i^-1 ) mod prime
     *
     * @param string $encryptedText The text to be reversed from the custom transformations.
     *
     * @return string The original plaintext prior to the custom encryption.
     */
    private function customDecrypt(string $encryptedText): string
    {
        $chars = mb_str_split($encryptedText, 1, '8bit');
        $reversedRounds = array_reverse($this->rounds);

        $reversed = array_map(function ($char) use ($reversedRounds) {
            $x = ord($char);
            foreach ($reversedRounds as $round) {
                $aInverse = $this->modInverse($round['a'], $this->prime);
                $x = ($x - $round['b']) % $this->prime;
                if ($x < 0) {
                    $x += $this->prime;
                }
                $x = ($x * $aInverse) % $this->prime;
            }
            return chr($x);
        }, $chars);

        return implode('', $reversed);
    }

    /**
     * adjustKeyLength
     *
     * Ensures the key is 32 bytes by hashing with SHA-256.
     *
     * @param string $key The user-supplied key.
     *
     * @return string 32-byte key for AES-256.
     */
    private function adjustKeyLength(string $key): string
    {
        return hash('sha256', $key, true);
    }

    /**
     * modInverse
     *
     * Computes modular inverse of a under modulo m using the Extended Euclidean Algorithm.
     *
     * @param int $a The integer to invert.
     * @param int $m The modulo.
     *
     * @return int The modular inverse of a mod m.
     *
     * @throws ObscuraException If no modular inverse exists (gcd != 1).
     */
    private function modInverse(int $a, int $m): int
    {
        // Extended Euclidean Algorithm to find x, y such that:
        // a*x + m*y = gcd(a, m) => a*x ≡ gcd(a, m) (mod m)
        // We want gcd(a, m) = 1 for invertibility, and a*x ≡ 1 (mod m).

        $a = $a % $m;
        [$gcd, $x] = $this->extendedGcd($a, $m);

        if ($gcd !== 1) {
            throw new ObscuraException("No modular inverse; gcd($a, $m) = $gcd != 1.");
        }

        // x might be negative, so normalize it in the range [0..m-1]
        $modInv = $x % $m;
        if ($modInv < 0) {
            $modInv += $m;
        }

        return $modInv;
    }

    /**
     * basicGcd
     *
     * A simple function to compute GCD without GMP.
     *
     * @param int $a
     * @param int $b
     *
     * @return int gcd(a, b)
     */
    private function basicGcd(int $a, int $b): int
    {
        while ($b !== 0) {
            $temp = $b;
            $b = $a % $b;
            $a = $temp;
        }
        return abs($a);
    }

    /**
     * extendedGcd
     *
     * The Extended Euclidean Algorithm. Returns [gcd, x, y] such that:
     *   gcd(a, b) = a*x + b*y
     * For our usage, we'll only return [gcd, x].
     *
     * @param int $a
     * @param int $b
     *
     * @return array{0: int, 1: int} An array containing gcd(a,b) and the coefficient x.
     */
    private function extendedGcd(int $a, int $b): array
    {
        if ($b === 0) {
            return [$a, 1]; // gcd(a,0)=a => a*1 + 0*0
        }

        $x0 = 1; 
        $x1 = 0;
        $y0 = 0; 
        $y1 = 1;

        $aa = $a;
        $bb = $b;

        while ($bb !== 0) {
            $q = intdiv($aa, $bb);

            $temp = $bb;
            $bb   = $aa % $bb;
            $aa   = $temp;

            $temp = $x1;
            $x1   = $x0 - $q * $x1;
            $x0   = $temp;

            $temp = $y1;
            $y1   = $y0 - $q * $y1;
            $y0   = $temp;
        }

        // gcd is aa
        // x0, y0 are the final coefficients
        return [$aa, $x0];
    }
}
