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
use Concrete\Package\AltchaCaptcha\Service\ReplayStore;

class AltchaController extends AbstractController implements CaptchaInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    private AltchaService $altcha;
    private ReplayStore $replayStore;

    public function __construct(AltchaService $altcha, ReplayStore $replayStore)
    {
        $this->altcha = $altcha;
        $this->replayStore = $replayStore;
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

        // The widget owns its hidden `altcha` form input. `auto="onsubmit"`
        // keeps the CAPTCHA frictionless and fetches a fresh challenge only
        // when the surrounding form is actually submitted.
        echo '<altcha-widget'
            . ' challengeurl="' . h($challengeUrl) . '"'
            . ' auto="onsubmit"'
            . ' floating'
            . ' hidefooter'
            . ' name="altcha"'
            . '></altcha-widget>';

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
        $rawPayload = $request->request->get('altcha');

        if (!is_string($rawPayload) || trim($rawPayload) === '') {
            $this->logWarning('Missing ALTCHA payload.');
            return false;
        }

        if (strlen($rawPayload) > 16384) {
            $this->logWarning('ALTCHA payload exceeds the accepted size.');
            return false;
        }

        try {
            if (!$this->altcha->verify($rawPayload)) {
                $this->logWarning('ALTCHA verification failed.');
                return false;
            }
        } catch (\Throwable $e) {
            $this->logWarning('ALTCHA verification raised an exception.');
            return false;
        }

        $replayKey = $this->altcha->getReplayKey($rawPayload);
        if ($replayKey === null) {
            $this->logWarning('ALTCHA payload has no usable replay key.');
            return false;
        }

        try {
            if (!$this->replayStore->claim($replayKey)) {
                $this->logWarning('ALTCHA replay attempt rejected.');
                return false;
            }
        } catch (\Throwable $e) {
            // Fail closed: an unavailable replay store must not silently turn
            // replay protection off.
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
        // No user-managed API credentials are required. Secrets are generated
        // locally by the package during installation/upgrade.
    }

    private function logWarning(string $message): void
    {
        if ($this->logger) {
            $this->logger->warning('[ALTCHA] ' . $message);
        }
    }
}
