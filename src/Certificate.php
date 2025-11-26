<?php

namespace DazzaDev\DgiiSvSigner;

use DazzaDev\DgiiSvSigner\Exceptions\CertificateException;

class Certificate
{
    /**
     * Path to certificate XML (.crt).
     */
    protected string $certificatePath;

    /**
     * Plain password to verify against stored SHA-512 hex.
     */
    protected string $privatePassword;

    /**
     * Loaded PEM private key.
     */
    protected string $privateKeyPem = '';

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $privatePassword)
    {
        $this->certificatePath = $certificatePath;
        $this->privatePassword = $privatePassword;
        $this->loadPrivateKeyPemFromXml();
    }

    /**
     * Get loaded PEM private key.
     */
    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * Load PEM private key from DGII/MH XML certificate file.
     * Mirrors Java CertificadoBusiness + Llave model (encodied + clave).
     *
     * @return string Private key PEM string.
     */
    public function loadPrivateKeyPemFromXml(): string
    {
        if (! is_file($this->certificatePath)) {
            throw new CertificateException('Certificate XML not found: '.$this->certificatePath);
        }

        $xml = new \DOMDocument;
        $xml->load($this->certificatePath);

        // Navigate expected structure: CertificadoMH/privateKey/*
        $privateKeyNode = self::queryFirst($xml, '//privateKey');
        if (! $privateKeyNode) {
            throw new CertificateException('Missing <privateKey> node in certificate XML.');
        }

        $claveNode = self::queryFirst($xml, '//privateKey/clave');
        $encodiedNode = self::queryFirst($xml, '//privateKey/encodied');
        $algorithmNode = self::queryFirst($xml, '//privateKey/algorithm');
        $formatNode = self::queryFirst($xml, '//privateKey/format');

        if (! $encodiedNode) {
            throw new CertificateException('Missing <encodied> in privateKey.');
        }

        // Verify password using SHA-512 hex (matches Java Cryptographic.encrypt)
        if ($claveNode) {
            $expectedHex = trim($claveNode->textContent);
            $providedHex = hash('sha512', $this->privatePassword);
            if (! hash_equals($expectedHex, $providedHex)) {
                throw new CertificateException('Invalid private key password.');
            }
        }

        $algorithm = $algorithmNode ? trim($algorithmNode->textContent) : 'RSA';
        $format = $formatNode ? trim($formatNode->textContent) : 'PKCS8';
        $raw = trim($encodiedNode->textContent);

        // Try base64 first;
        $der = base64_decode($raw, true);
        if ($der === false) {
            // Fallback: parse comma-separated bytes (e.g., "1,2,3")
            $bytes = array_map('intval', array_filter(array_map('trim', explode(',', $raw)), fn ($v) => $v !== ''));
            $der = self::bytesToBinary($bytes);
        }

        // Convert DER to PEM with proper header
        $this->privateKeyPem = self::derToPemPrivateKey($der, $format);

        return $this->privateKeyPem;
    }

    /**
     * Convert DER-encoded binary to PEM-formatted private key.
     */
    private static function derToPemPrivateKey(string $der, string $format = 'PKCS8'): string
    {
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        $header = ($format === 'PKCS1') ? 'BEGIN RSA PRIVATE KEY' : 'BEGIN PRIVATE KEY';
        $footer = ($format === 'PKCS1') ? 'END RSA PRIVATE KEY' : 'END PRIVATE KEY';

        return "-----$header-----\n".$b64."-----$footer-----\n";
    }

    /**
     * Convert array of byte integers to binary string.
     */
    private static function bytesToBinary(array $bytes): string
    {
        return pack('C*', ...$bytes);
    }

    /**
     * Base64 URL-safe decoding.
     */
    public static function base64urlDecode(string $data): string
    {
        $replaced = strtr($data, '-_', '+/');
        $pad = strlen($replaced) % 4;
        if ($pad) {
            $replaced .= str_repeat('=', 4 - $pad);
        }

        return base64_decode($replaced);
    }

    /**
     * Query first DOMNode matching XPath.
     */
    private static function queryFirst(\DOMDocument $xml, string $xpath): ?\DOMNode
    {
        $xp = new \DOMXPath($xml);
        $nodelist = $xp->query($xpath);
        if ($nodelist && $nodelist->length > 0) {
            return $nodelist->item(0);
        }

        return null;
    }
}
