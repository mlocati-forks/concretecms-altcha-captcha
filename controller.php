<?php

namespace Concrete\Package\AltchaCaptcha;

use Concrete\Core\Asset\Asset;
use Concrete\Core\Asset\AssetList;
use Concrete\Core\Captcha\Library as CaptchaLibrary;
use Concrete\Core\Entity\Package as PackageEntity;
use Concrete\Core\Package\Package;

class Controller extends Package
{
    protected $pkgHandle = 'altcha_captcha';
    protected $pkgVersion = '1.0.2';
    protected $appVersionRequired = '9.0.0';
    protected $phpVersionRequired = '8.1';

    protected $pkgAutoloaderRegistries = [
        'src/' => 'Concrete\\Package\\AltchaCaptcha',
    ];

    public function getPackageName()
    {
        return t('ALTCHA CAPTCHA');
    }

    public function getPackageDescription()
    {
        return t('Self-hosted, privacy-friendly proof-of-work bot protection for Concrete CMS.');
    }

    public function on_start()
    {
        $this->loadVendorAutoloader();
        $this->registerAssets();

        $router = $this->app->make('router');
        (new RouteList())->loadRoutes($router);
    }

    public function install()
    {
        $this->requireAltchaDependency();

        $pkg = parent::install();

        $this->ensureSecret();
        $this->ensureCaptchaLibrary($pkg);
        $this->registerAssets();

        return $pkg;
    }

    public function upgrade()
    {
        $this->requireAltchaDependency();
        parent::upgrade();

        $this->ensureSecret();

        $pkg = $this->getPackageEntity();
        if ($pkg !== null) {
            $this->ensureCaptchaLibrary($pkg);
        }
    }

    public function uninstall()
    {
        parent::uninstall();

        $db = $this->app->make('database')->connection();
        if ($db->tableExists('AltchaCaptchaUsedChallenges')) {
            $db->executeStatement('DROP TABLE AltchaCaptchaUsedChallenges');
        }
    }

    protected function registerAssets(): void
    {
        $assetList = AssetList::getInstance();

        $assetList->register(
            'javascript',
            'altcha',
            'js/altcha.js',
            [
                'position' => Asset::ASSET_POSITION_FOOTER,
                'version' => $this->pkgVersion,
            ],
            $this
        );

        $assetList->register(
            'css',
            'altcha',
            'css/altcha.css',
            [
                'position' => Asset::ASSET_POSITION_FOOTER,
                'version' => $this->pkgVersion,
            ],
            $this
        );
    }

    private function ensureSecret(): void
    {
        $config = $this->getConfig();
        $secret = (string) $config->get('settings.hmac_key', '');

        if (!preg_match('/^[a-f0-9]{64}$/i', $secret)) {
            $config->save('settings.hmac_key', bin2hex(random_bytes(32)));
        }
    }

    private function ensureCaptchaLibrary(PackageEntity $pkg): void
    {
        if (!CaptchaLibrary::getByHandle('altcha')) {
            CaptchaLibrary::add('altcha', t('ALTCHA CAPTCHA'), $pkg);
        }
    }

    private function loadVendorAutoloader(): void
    {
        if (class_exists('AltchaOrg\\Altcha\\V1\\Altcha')) {
            return;
        }

        $vendorAutoloader = __DIR__ . '/vendor/autoload.php';
        if (is_file($vendorAutoloader)) {
            require_once $vendorAutoloader;
        }
    }

    private function requireAltchaDependency(): void
    {
        $this->loadVendorAutoloader();

        if (!class_exists('AltchaOrg\\Altcha\\V1\\Altcha')) {
            throw new \RuntimeException(
                t('ALTCHA PHP dependency is missing. Run "composer install --no-dev --optimize-autoloader" inside the package directory before installing or upgrading the package.')
            );
        }
    }
}
