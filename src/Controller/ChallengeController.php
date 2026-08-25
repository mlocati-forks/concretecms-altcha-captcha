<?php

namespace Concrete\Package\AltchaCaptcha\Controller;

use Concrete\Core\Controller\AbstractController;
use Concrete\Package\AltchaCaptcha\Service\AltchaService;
use Symfony\Component\HttpFoundation\JsonResponse;

class ChallengeController extends AbstractController
{
    private AltchaService $altcha;

    public function __construct(AltchaService $altcha)
    {
        $this->altcha = $altcha;
        parent::__construct();
    }

    public function challenge(): JsonResponse
    {
        $headers = [
            'Cache-Control' => 'no-store, no-cache, must-revalidate, private',
            'Pragma' => 'no-cache',
            'X-Content-Type-Options' => 'nosniff',
        ];

        if (!$this->altcha->isAvailable()) {
            return new JsonResponse(
                ['error' => 'ALTCHA is not configured.'],
                JsonResponse::HTTP_SERVICE_UNAVAILABLE,
                $headers
            );
        }

        try {
            return new JsonResponse(
                $this->altcha->createChallenge(),
                JsonResponse::HTTP_OK,
                $headers
            );
        } catch (\Throwable $e) {
            return new JsonResponse(
                ['error' => 'Unable to create ALTCHA challenge.'],
                JsonResponse::HTTP_INTERNAL_SERVER_ERROR,
                $headers
            );
        }
    }
}
