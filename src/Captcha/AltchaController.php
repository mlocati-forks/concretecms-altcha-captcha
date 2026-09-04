<?php

namespace Concrete\Package\AltchaCaptcha\Captcha;

use Concrete\Core\Captcha\CaptchaInterface;
use Concrete\Core\Controller\AbstractController;
use Concrete\Core\Http\Request;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerAwareInterface;
use Concrete\Core\Logging\LoggerAwareTrait;
use Concrete\Core\Support\Facade\Url;
use Concrete\Core\View\View;
use Concrete\Package\AltchaCaptcha\Service\AltchaService;
use Concrete\Package\AltchaCaptcha\Service\RateLimiter;
use Concrete\Package\AltchaCaptcha\Service\ReplayStore;

class AltchaController extends AbstractController implements CaptchaInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    private AltchaService $altcha;
    private ReplayStore $replayStore;
    private RateLimiter $rateLimiter;

    public function __construct(
        AltchaService $altcha,
        ReplayStore $replayStore,
        RateLimiter $rateLimiter
    ) {
        $this->altcha = $altcha;
        $this->replayStore = $replayStore;
        $this->rateLimiter = $rateLimiter;
        parent::__construct();
    }

    public function getLoggerChannel()
    {
        return Channels::CHANNEL_SPAM;
    }

    public function display(array $options = []): string
    {
        if (!$this->altcha->isAvailable()) {
            echo '<div class="alert alert-warning">' . h(t('ALTCHA is not configured correctly.')) . '</div>';
            return '';
        }

        $challengeUrl = (string) Url::to('/altcha-captcha/challenge');
        $workerUrl = $this->altcha->getWorkerUrl();
        $instanceId = 'altcha-captcha-' . bin2hex(random_bytes(6));

        echo '<div'
            . ' id="' . h($instanceId) . '"'
            . ' class="altcha-captcha"'
            . ' data-altcha-captcha'
            . ' data-challenge-url="' . h($challengeUrl) . '"'
            . ' data-worker-url="' . h($workerUrl) . '"'
            . ' data-text-verifying="' . h(t('Security check…')) . '"'
            . ' data-text-verified="' . h(t('Verified')) . '"'
            . ' data-text-error="' . h(t('Verification failed. Please try again.')) . '"'
            . ' data-text-rate-limited="' . h(t('Too many verification attempts. Please try again later.')) . '"'
            . '>';

        echo '<input type="hidden" name="altcha" value="" data-altcha-payload>';

        // Off-screen honeypot: ignored by normal users and assistive technology,
        // but commonly populated by generic form-filling bots.
        echo '<span class="altcha-captcha-honeypot" aria-hidden="true">'
            . '<label for="' . h($instanceId . '-website') . '">' . h(t('Website')) . '</label>'
            . '<input'
            . ' id="' . h($instanceId . '-website') . '"'
            . ' type="text"'
            . ' name="altcha_captcha_website"'
            . ' value=""'
            . ' tabindex="-1"'
            . ' autocomplete="off"'
            . ' data-altcha-honeypot'
            . '>'
            . '</span>';

        echo '<div class="altcha-captcha-status" data-altcha-status hidden role="status" aria-live="polite">'
            . '<span class="altcha-captcha-indicator" aria-hidden="true"></span>'
            . '<span class="altcha-captcha-message" data-altcha-message></span>'
            . '</div>';

        echo '</div>';

        View::getInstance()->requireAsset('javascript', 'altcha');
        View::getInstance()->requireAsset('css', 'altcha');

        return '';
    }

    public function label()
    {
        return '';
    }

    public function check(): bool
    {
        $request = Request::getInstance();

        $honeypot = $request->request->get('altcha_captcha_website');
        if (is_string($honeypot) && trim($honeypot) !== '') {
            $this->logWarning('Honeypot submission rejected.');
            return false;
        }

        try {
            $rate = $this->rateLimiter->consume(
                'verification',
                RateLimiter::VERIFICATION_LIMIT,
                $request->getClientIp()
            );
            if (!$rate['allowed']) {
                $this->logWarning('Verification rate limit exceeded.');
                return false;
            }
        } catch (\Throwable $e) {
            // Fail closed: rate limiting is a security control, not telemetry.
            $this->logWarning('ALTCHA rate limiter is unavailable.');
            return false;
        }

        $rawPayload = $request->request->get('altcha');
        if (!is_string($rawPayload) || trim($rawPayload) === '') {
            $this->logWarning('Missing ALTCHA payload.');
            return false;
        }

        if (strlen($rawPayload) > 32768) {
            $this->logWarning('ALTCHA payload exceeds the accepted size.');
            return false;
        }

        try {
            $verification = $this->altcha->verify($rawPayload);
            if (!$verification['verified']) {
                $this->logWarning(sprintf(
                    'ALTCHA verification failed (expired=%s, invalidSignature=%s, invalidSolution=%s).',
                    $verification['expired'] ? '1' : '0',
                    $verification['invalidSignature'] === null ? 'null' : ($verification['invalidSignature'] ? '1' : '0'),
                    $verification['invalidSolution'] === null ? 'null' : ($verification['invalidSolution'] ? '1' : '0')
                ));
                return false;
            }
        } catch (\Throwable $e) {
            $this->logWarning(sprintf(
                'ALTCHA verification raised %s: %s',
                get_class($e),
                $e->getMessage()
            ));
            return false;
        }

        $claim = $this->altcha->getReplayClaim($rawPayload);
        if ($claim === null) {
            $this->logWarning('ALTCHA payload has no usable replay metadata.');
            return false;
        }

        try {
            if (!$this->replayStore->claim($claim['hash'], $claim['expiresAt'])) {
                $this->logWarning('ALTCHA replay attempt rejected.');
                return false;
            }
        } catch (\Throwable $e) {
            $this->logWarning('ALTCHA replay protection is unavailable.');
            return false;
        }

        return true;
    }

    public function showInput()
    {
        if (!$this->altcha->isAvailable()) {
            return '<div class="alert alert-warning">'
                . h(t('ALTCHA is not configured correctly. Reinstall or upgrade the package to generate a local secret.'))
                . '</div>';
        }

        return '';
    }

    public function saveOptions($data)
    {
        // No user-managed API credentials are required.
    }

    private function logWarning(string $message): void
    {
        if ($this->logger) {
            $this->logger->warning('[ALTCHA] ' . $message);
        }
    }
}
