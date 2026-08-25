<?php

namespace Concrete\Package\AltchaCaptcha;

use Concrete\Core\Routing\RouteListInterface;
use Concrete\Core\Routing\Router;

class RouteList implements RouteListInterface
{
    public function loadRoutes(Router $router)
    {
        $router
            ->get(
                '/altcha-captcha/challenge',
                'Concrete\\Package\\AltchaCaptcha\\Controller\\ChallengeController::challenge'
            )
            ->setName('altcha_captcha.challenge');
    }
}
