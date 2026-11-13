<?php
/* LinkVault – Schlüssel und Verschlüsselung */
defined('LV_VERSION') || exit;

/* ---------- Schlüssel aus Passwort wickeln ---------- */

function lvDeriveKek(string $password, string $saltBin, int $iters): string {
    return hash_pbkdf2('sha256', $password, $saltBin, max(10000, $iters), 32, true);
}

function lvWrapKey(string $dek, string $password): array {
    $salt = random_bytes(16);
    $iters = LV_KDF_ITERS;
    $kek = lvDeriveKek($password, $salt, $iters);
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($dek, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new Exception('Schlüssel konnte nicht geschützt werden.');
    return [
        'kdf_salt' => base64_encode($salt),
        'wrapped_key' => base64_encode($iv . $tag . $ct),
        'kdf_iters' => $iters,
    ];
}

function lvUnwrapKey(string $password, array $cfg): ?string {
    $salt = base64_decode((string)$cfg['kdf_salt'], true);
    $blob = base64_decode((string)$cfg['wrapped_key'], true);
    if ($salt === false || $blob === false || strlen($blob) < 28) return null;
    $iters = (int)($cfg['kdf_iters'] ?? LV_KDF_ITERS);
    $kek = lvDeriveKek($password, $salt, $iters);
    $iv = substr($blob, 0, 12);
    $tag = substr($blob, 12, 16);
    $ct = substr($blob, 28);
    $dek = openssl_decrypt($ct, 'aes-256-gcm', $kek, OPENSSL_RAW_DATA, $iv, $tag);
    if ($dek === false || strlen($dek) !== 32) return null;
    return $dek;
}

/* ---------- Verschlüsselung (AES-256-GCM) ---------- */

function lvEncryptWith(string $key, string $plain): string {
    $iv = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new Exception('Verschlüsselung fehlgeschlagen.');
    return 'LVENC1' . base64_encode($iv . $tag . $ct);
}

function lvDecryptWith(string $key, string $data): ?string {
    if (strncmp($data, 'LVENC1', 6) !== 0) return null;
    $raw = base64_decode(substr($data, 6), true);
    if ($raw === false || strlen($raw) < 28) return null;
    $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    return $plain === false ? null : $plain;
}
