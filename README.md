# DGII Signer 🇸🇻

Paquete para firmar documento tributario electrónico (DTE) (Factura, Nota de remisión, Nota crédito, Nota débito y Comprobante de retención) basado en las especificaciones de la Dirección General de Impuestos Internos (DGII) de El Salvador.

## Instalación

```bash
composer require dazza-dev/dgii-sv-signer
```

## Guía de uso

```php
use DazzaDev\DgiiSvSigner\Signer;

// Instanciar el signer
$signer = new Signer(
    certificatePath: __DIR__ . '/certificado.crt',
    privatePassword: 'clave_privada',
);

// Firmar el Json
$signedJson = $signer->sign($jsonDocument);
```

## Envío de Documento firmado

Una vez firmado el Documento, puedes enviarlo al DGII usando el paquete [DGII Sender](https://github.com/dazza-dev/dgii-sv-sender).

## Contribuciones

Contribuciones son bienvenidas. Si encuentras algún error o tienes ideas para mejoras, por favor abre un issue o envía un pull request. Asegúrate de seguir las guías de contribución.

## Autor

DGII Signer fue creado por [DAZZA](https://github.com/dazza-dev).

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](https://opensource.org/licenses/MIT).
