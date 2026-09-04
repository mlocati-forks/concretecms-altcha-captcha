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
     * Atomically claim a successfully verified challenge until its signed
     * expiration time. The primary key rejects concurrent replays as well.
     */
    public function claim(string $challengeHash, int $expiresAt): bool
    {
        $now = time();
        if ($expiresAt <= $now) {
            return false;
        }

        $this->connection->executeStatement(
            'DELETE FROM AltchaCaptchaUsedChallenges WHERE expiresAt < ?',
            [$now]
        );

        try {
            $this->connection->insert('AltchaCaptchaUsedChallenges', [
                'challengeHash' => $challengeHash,
                'expiresAt' => $expiresAt,
            ]);
        } catch (UniqueConstraintViolationException $e) {
            return false;
        }

        return true;
    }
}
