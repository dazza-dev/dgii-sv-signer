<?php

namespace DazzaDev\DgiiSvSigner;

use DazzaDev\DgiiSvSigner\Exceptions\SignerException;

class Signer
{
    /**
     * Certificate
     */
    protected Certificate $certificate;

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $privatePassword)
    {
        $this->certificate = new Certificate($certificatePath, $privatePassword);
    }

    /**
     * Create a JWS Compact Serialization string using RS512.
     *
     * @param  string  $payloadJson  Raw JSON string to sign (DTE content).
     * @param  string  $privateKeyPem  Private key in PEM (PKCS#8 or PKCS#1) format.
     * @param  array  $header  Additional JOSE headers to merge. Default adds only alg RS512.
     * @return string Compact JWS string: base64url(header).base64url(payload).base64url(signature)
     */
    public function sign(string $payloadJson): string
    {
        $jwsHeader = [
            'alg' => 'RS512',
        ];
        $headerB64 = self::base64urlEncode(json_encode($jwsHeader, JSON_UNESCAPED_SLASHES));
        $payloadB64 = self::base64urlEncode($payloadJson);
        $signingInput = $headerB64.'.'.$payloadB64;

        $pkey = openssl_pkey_get_private($this->certificate->getPrivateKeyPem());
        if ($pkey === false) {
            throw new SignerException('Unable to load private key. Ensure PEM is valid and OpenSSL is enabled.');
        }

        $signature = '';
        $ok = openssl_sign($signingInput, $signature, $pkey, OPENSSL_ALGO_SHA512);
        if ($ok !== true) {
            throw new SignerException('Failed to sign payload with RS512.');
        }

        return $signingInput.'.'.self::base64urlEncode($signature);
    }

    /**
     * Base64 URL-safe encoding.
     */
    public static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
