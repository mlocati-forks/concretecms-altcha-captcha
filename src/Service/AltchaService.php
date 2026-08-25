<?php

namespace Concrete\Package\AltchaCaptcha\Service;

use AltchaOrg\Altcha\V1\Altcha;
use AltchaOrg\Altcha\V1\ChallengeOptions;
use AltchaOrg\Altcha\V1\Hasher\Algorithm;
use Concrete\Core\Package\PackageService;

class AltchaService
{
    private PackageService $packageService;

    public function __construct(PackageService $packageService)
    {
        $this->packageService = $packageService;
    }

    /**
     * Challenges are fetched when the widget actually needs one, so a longer
     * lifetime does not make form entry fragile while still keeping replay
     * records short-lived.
     */
    public const CHALLENGE_TTL = 300;

    /**
     * Keep the browser work noticeable to bots but normally unobtrusive to a
     * human user. This is intentionally easy to tune in one place.
     */
    public const MAX_NUMBER = 250000;

    public function isAvailable(): bool
    {
        return class_exists(Altcha::class) && $this->getSecret() !== null;
    }

    public function createChallenge(): array
    {
        $altcha = $this->createClient();
        $challenge = $altcha->createChallenge(new ChallengeOptions(
            algorithm: Algorithm::SHA256,
            maxNumber: self::MAX_NUMBER,
            expires: (new \DateTimeImmutable())->modify('+' . self::CHALLENGE_TTL . ' seconds')
        ));

        return [
            'algorithm' => $challenge->algorithm,
            'challenge' => $challenge->challenge,
            'maxNumber' => $challenge->maxNumber,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
        ];
    }

    public function verify(string $payload): bool
    {
        return $this->createClient()->verifySolution($payload, true);
    }

    /**
     * Return a privacy-preserving, challenge-specific replay key.
     *
     * The signature is part of the ALTCHA payload and is authenticated by the
     * HMAC check before this key is claimed. We store only its SHA-256 hash.
     */
    public function getReplayKey(string $payload): ?string
    {
        $decoded = base64_decode($payload, true);
        if ($decoded === false) {
            return null;
        }

        try {
            $data = json_decode($decoded, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return null;
        }

        if (!is_array($data) || !isset($data['signature']) || !is_string($data['signature'])) {
            return null;
        }

        $signature = trim($data['signature']);
        if ($signature === '') {
            return null;
        }

        return hash('sha256', $signature);
    }

    private function createClient(): Altcha
    {
        $secret = $this->getSecret();
        if ($secret === null) {
            throw new \RuntimeException('ALTCHA HMAC secret is not configured.');
        }

        return new Altcha($secret);
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
}
