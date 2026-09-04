<?php

namespace Concrete\Package\AltchaCaptcha\Service;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\VerifySolutionOptions;
use Concrete\Core\Package\PackageService;

class AltchaService
{
    public const CHALLENGE_TTL = 300;
    public const PBKDF2_COST = 1500;
    public const COUNTER_MIN = 500;
    public const COUNTER_MAX = 1200;

    private PackageService $packageService;

    public function __construct(PackageService $packageService)
    {
        $this->packageService = $packageService;
    }

    public function isAvailable(): bool
    {
        return class_exists(Altcha::class)
            && class_exists(Pbkdf2::class)
            && $this->getSecret() !== null;
    }

    /**
     * Create a PoW v2 challenge using PBKDF2/SHA-256 in deterministic mode.
     *
     * 1.1.2 intentionally uses a lighter interactive profile than the upstream
     * example defaults because this package verifies ordinary form submissions
     * invisibly. Rate limiting, honeypot and replay protection remain separate
     * layers around the proof-of-work.
     *
     * A separate derived HMAC key-signature secret enables ALTCHA's fast
     * verification path, so the server does not repeat the browser's PBKDF2
     * work when a form is submitted.
     */
    public function createChallenge(): array
    {
        $challenge = $this->createClient()->createChallenge(new CreateChallengeOptions(
            algorithm: new Pbkdf2(),
            cost: self::PBKDF2_COST,
            counter: random_int(self::COUNTER_MIN, self::COUNTER_MAX),
            expiresAt: time() + self::CHALLENGE_TTL
        ));

        return $challenge->toArray();
    }

    /**
     * Verify a submitted PoW v2 payload and expose non-sensitive diagnostics.
     *
     * @return array{verified:bool, expired:bool, invalidSignature:?bool, invalidSolution:?bool, time:float}
     */
    public function verify(string $payload): array
    {
        $result = $this->createClient()->verifySolution(new VerifySolutionOptions(
            payload: $payload,
            algorithm: new Pbkdf2()
        ));

        return [
            'verified' => (bool) $result->verified,
            'expired' => (bool) $result->expired,
            'invalidSignature' => $result->invalidSignature,
            'invalidSolution' => $result->invalidSolution,
            'time' => (float) $result->time,
        ];
    }

    /**
     * Extract replay metadata only after cryptographic verification succeeded.
     *
     * @return array{hash:string, expiresAt:int}|null
     */
    public function getReplayClaim(string $payload): ?array
    {
        $data = $this->decodePayload($payload);
        if ($data === null) {
            return null;
        }

        $signature = $data['challenge']['signature'] ?? null;
        $expiresAt = $data['challenge']['parameters']['expiresAt'] ?? null;

        if (!is_string($signature) || trim($signature) === '') {
            return null;
        }

        if (!is_int($expiresAt) && !(is_string($expiresAt) && ctype_digit($expiresAt))) {
            return null;
        }

        $expiresAt = (int) $expiresAt;
        if ($expiresAt <= time()) {
            return null;
        }

        return [
            'hash' => hash('sha256', trim($signature)),
            'expiresAt' => $expiresAt,
        ];
    }

    /**
     * Create a stable, privacy-preserving token for short-lived rate limiting.
     */
    public function hashClientIdentifier(string $purpose, ?string $clientIp): string
    {
        $secret = $this->getSecret();
        if ($secret === null) {
            throw new \RuntimeException('ALTCHA HMAC secret is not configured.');
        }

        $identifier = trim((string) $clientIp);
        if ($identifier === '') {
            $identifier = 'unknown-client';
        }

        return hash_hmac('sha256', $purpose . "\0" . $identifier, $secret);
    }

    /**
     * Return the public URL of the self-hosted worker script.
     */
    public function getWorkerUrl(): string
    {
        $controller = $this->packageService->getClass('altcha_captcha');
        return rtrim((string) $controller->getRelativePath(), '/')
            . '/js/vendor/altcha-pbkdf2-worker.js?v=' . rawurlencode((string) $controller->getPackageVersion());
    }

    private function createClient(): Altcha
    {
        $secret = $this->getSecret();
        if ($secret === null) {
            throw new \RuntimeException('ALTCHA HMAC secret is not configured.');
        }

        // Keep signature duties cryptographically separated without requiring
        // administrators to manage a second secret.
        $keySignatureSecret = hash_hmac(
            'sha256',
            'altcha-captcha-v2-key-signature',
            $secret
        );

        return new Altcha(
            hmacSignatureSecret: $secret,
            hmacKeySignatureSecret: $keySignatureSecret
        );
    }

    private function getSecret(): ?string
    {
        try {
            $controller = $this->packageService->getClass('altcha_captcha');
        } catch (\Throwable $e) {
            return null;
        }

        $secret = (string) $controller->getConfig()->get('settings.hmac_key', '');
        if (!preg_match('/^[a-f0-9]{64}$/i', $secret)) {
            return null;
        }

        return strtolower($secret);
    }

    private function decodePayload(string $payload): ?array
    {
        $decoded = base64_decode($payload, true);
        if ($decoded === false) {
            return null;
        }

        try {
            $data = json_decode($decoded, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return null;
        }

        return is_array($data) ? $data : null;
    }
}
