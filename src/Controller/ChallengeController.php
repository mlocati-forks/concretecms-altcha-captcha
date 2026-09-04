<?php

namespace Concrete\Package\AltchaCaptcha\Controller;

use Concrete\Core\Controller\AbstractController;
use Concrete\Core\Http\Request;
use Concrete\Core\Support\Facade\Log;
use Concrete\Package\AltchaCaptcha\Service\AltchaService;
use Concrete\Package\AltchaCaptcha\Service\RateLimiter;
use Symfony\Component\HttpFoundation\JsonResponse;

class ChallengeController extends AbstractController
{
    private AltchaService $altcha;
    private RateLimiter $rateLimiter;

    public function __construct(AltchaService $altcha, RateLimiter $rateLimiter)
    {
        $this->altcha = $altcha;
        $this->rateLimiter = $rateLimiter;
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
            $request = Request::getInstance();
            $rate = $this->rateLimiter->consume(
                'challenge',
                RateLimiter::CHALLENGE_LIMIT,
                $request->getClientIp()
            );

            $headers['X-RateLimit-Limit'] = (string) $rate['limit'];
            $headers['X-RateLimit-Remaining'] = (string) $rate['remaining'];

            if (!$rate['allowed']) {
                $headers['Retry-After'] = (string) $rate['retryAfter'];
                return new JsonResponse(
                    ['error' => 'Too many CAPTCHA challenges. Please try again later.'],
                    JsonResponse::HTTP_TOO_MANY_REQUESTS,
                    $headers
                );
            }

            return new JsonResponse(
                $this->altcha->createChallenge(),
                JsonResponse::HTTP_OK,
                $headers
            );
        } catch (\Throwable $e) {
            Log::addError(sprintf(
                '[ALTCHA] Challenge generation failed (%s): %s',
                get_class($e),
                $e->getMessage()
            ));

            return new JsonResponse(
                ['error' => 'Unable to create ALTCHA challenge.'],
                JsonResponse::HTTP_INTERNAL_SERVER_ERROR,
                $headers
            );
        }
    }
}
