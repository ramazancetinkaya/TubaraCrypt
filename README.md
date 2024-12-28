# Obscura - AES Cryptor

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-8.0%2B-blue)](https://www.php.net/)
[![Issues](https://img.shields.io/github/issues/ramazancetinkaya/ObscuraCrypt?color=green)](https://github.com/ramazancetinkaya/ObscuraCrypt/issues)
[![Stars](https://img.shields.io/github/stars/ramazancetinkaya/ObscuraCrypt?color=yellow)](https://github.com/ramazancetinkaya/ObscuraCrypt/stargazers)
[![Forks](https://img.shields.io/github/forks/ramazancetinkaya/ObscuraCrypt?color=lightgrey)](https://github.com/ramazancetinkaya/ObscuraCrypt/network)

**Obscura** is an advanced PHP cryptography library that combines robust AES encryption (AES-256-CBC by default) with a multi-round polynomial-based custom encryption layer for enhanced security. It also supports URL-safe Base64 encoding when desired.

<a href="https://github.com/ramazancetinkaya/ObscuraCrypt/issues">Report a Bug</a>
·
<a href="https://github.com/ramazancetinkaya/ObscuraCrypt/pulls">New Pull Request</a>

> **No GMP extension needed** – everything is done via the **Extended Euclidean Algorithm** for modular arithmetic.

> **Disclaimer:** This code is presented for educational purposes. For production environments, ensure that you have conducted a thorough security review and implemented best practices for key management, tamper detection, and environment-specific compliance requirements.

## ⭐ Support the Project

If you find this library helpful, please consider giving it a star on GitHub. Your support helps improve and maintain the project. Thank you! 🌟

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [URL-safe Base64 Example](#url-safe-base64-example)
- [Contributing](#contributing)
- [License](#license)

## Features

- **AES-256-CBC**: Provides a strong, battle-tested encryption foundation via OpenSSL.
- **Multi-Round Custom Layer**: Applies multiple polynomial transformations on each character, making cryptanalysis more challenging.
- **No GMP Dependency**: Uses the Extended Euclidean Algorithm for modular inverse, so **GMP** is not required.
- **URL-Safe Base64 Option**: Encrypt once, share anywhere. Prevents `+`, `/`, and `=` characters from breaking URLs.
- **Strict Typing**: Leverages PHP 8.0+ features and enforces strict typing for reliability.
- **Custom Exceptions**: Throws a `CryptoException` for all encryption/decryption errors, making error handling straightforward.

## Installation

You can install the `Obscura` library using [Composer](https://getcomposer.org/). Run the following command in your terminal:

```bash
composer require ramazancetinkaya/obscura
```

This command adds the library to your composer.json and installs it in the vendor/ directory.

## Usage

Below are quick examples demonstrating how to use Obscura in your PHP project.

### Basic Example

```php
<?php

require 'vendor/autoload.php';

use ramazancetinkaya\Obscura;
use ramazancetinkaya\ObscuraException;

try {
    // Create an Obscura instance
    $secretKey = 'my-super-secure-key';
    $obscura   = new Obscura($secretKey);

    // Data to encrypt
    $plainText = 'Hello World!';

    // Encrypt
    $encrypted = $obscura->encrypt($plainText);
    echo "Encrypted (base64): " . $encrypted . PHP_EOL;

    // Decrypt
    $decrypted = $obscura->decrypt($encrypted);
    echo "Decrypted: " . $decrypted . PHP_EOL;

} catch (ObscuraException $e) {
    echo "Error: " . $e->getMessage();
}
```

### URL-safe Base64 Example

If you prefer URL-safe Base64 encoding (e.g. for inclusion in GET parameters), you can enable it via the constructor:

```php
<?php

require 'vendor/autoload.php';

use ramazancetinkaya\Obscura;
use ramazancetinkaya\ObscuraException;

try {
    // URL-safe Obscura instance
    $secretKey   = 'my-super-secure-key';
    $obscuraSafe = new Obscura($secretKey, 'aes-256-cbc', true);

    // Data to encrypt
    $plainUrl = 'https://example.com?param=someValue';

    // Encrypt (URL-safe)
    $encryptedUrl = $obscuraSafe->encrypt($plainUrl);
    echo "Encrypted (URL-safe): " . $encryptedUrl . PHP_EOL;

    // Decrypt
    $decryptedUrl = $obscuraSafe->decrypt($encryptedUrl);
    echo "Decrypted URL: " . $decryptedUrl . PHP_EOL;

} catch (ObscuraException $e) {
    echo "Error: " . $e->getMessage();
}
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
