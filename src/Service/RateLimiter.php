<?php

namespace Concrete\Package\AltchaCaptcha\Service;

use Concrete\Core\Database\Connection\Connection;

class RateLimiter
{
    public const WINDOW_SECONDS = 600;
    public const CHALLENGE_LIMIT = 20;
    public const VERIFICATION_LIMIT = 10;

    private Connection $connection;
    private AltchaService $altcha;

    public function __construct(Connection $connection, AltchaService $altcha)
    {
        $this->connection = $connection;
        $this->altcha = $altcha;
    }

    /**
     * Consume one request from a fixed-window, privacy-preserving bucket.
     *
     * Only an HMAC of purpose + client IP is stored. Raw IP addresses never
     * enter the package database.
     *
     * @return array{allowed:bool, limit:int, remaining:int, retryAfter:int}
     */
    public function consume(string $purpose, int $limit, ?string $clientIp): array
    {
        $this->ensureTable();

        $now = time();
        $window = self::WINDOW_SECONDS;
        $windowStart = intdiv($now, $window) * $window;
        $expiresAt = $windowStart + $window;
        $clientHash = $this->altcha->hashClientIdentifier($purpose, $clientIp);
        $rateKey = hash('sha256', $purpose . "\0" . $clientHash . "\0" . $windowStart);

        // Opportunistic cleanup keeps the table bounded without a cron job.
        $this->connection->executeStatement(
            'DELETE FROM AltchaCaptchaRateLimits WHERE expiresAt < ?',
            [$now]
        );

        // Concrete CMS supports MySQL/MariaDB. This statement increments the
        // fixed-window counter atomically even with parallel PHP workers.
        $this->connection->executeStatement(
            'INSERT INTO AltchaCaptchaRateLimits (rateKey, requestCount, expiresAt) VALUES (?, 1, ?) '
            . 'ON DUPLICATE KEY UPDATE requestCount = requestCount + 1, expiresAt = ?',
            [$rateKey, $expiresAt, $expiresAt]
        );

        $count = (int) $this->connection->fetchOne(
            'SELECT requestCount FROM AltchaCaptchaRateLimits WHERE rateKey = ?',
            [$rateKey]
        );

        return [
            'allowed' => $count <= $limit,
            'limit' => $limit,
            'remaining' => max(0, $limit - $count),
            'retryAfter' => max(1, $expiresAt - $now),
        ];
    }

    private function ensureTable(): void
    {
        if ($this->connection->tableExists('AltchaCaptchaRateLimits')) {
            return;
        }

        $this->connection->executeStatement(
            'CREATE TABLE IF NOT EXISTS AltchaCaptchaRateLimits ('
            . 'rateKey VARCHAR(64) NOT NULL, '
            . 'requestCount INT UNSIGNED NOT NULL DEFAULT 0, '
            . 'expiresAt INT UNSIGNED NOT NULL, '
            . 'PRIMARY KEY (rateKey), '
            . 'INDEX idxAltchaCaptchaRateExpiresAt (expiresAt)'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );
    }

}
