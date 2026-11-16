<?php
namespace OPNsense\XGuardGateway\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

/**
 * Class SettingsController Handles settings related API actions for the XGuardGateway module
 * @package OPNsense\XGuardGateway
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = "\OPNsense\XGuardGateway\XGuardGateway";
    protected static $internalModelName = "xguardgateway";
}
