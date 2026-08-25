<?php

namespace Concrete\Package\AltchaCaptcha\Service;

use Concrete\Core\Database\Connection\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;

class ReplayStore
{
    private Connection $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * Atomically claim a successfully verified challenge.
     *
     * Only successful CAPTCHA submissions reach this method. Expired rows are
     * removed first, so this table contains only a short rolling replay window.
     */
    public function claim(string $challengeHash): bool
    {
        $now = time();

        $this->connection->executeStatement(
            'DELETE FROM AltchaCaptchaUsedChallenges WHERE expiresAt < ?',
            [$now]
        );

        try {
            $this->connection->insert('AltchaCaptchaUsedChallenges', [
                'challengeHash' => $challengeHash,
                'expiresAt' => $now + AltchaService::CHALLENGE_TTL,
            ]);
        } catch (UniqueConstraintViolationException $e) {
            return false;
        }

        return true;
    }
}
