<?php
namespace OPNsense\XGuardGateway\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\XGuardGateway
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceName = "xguardgateway";
    protected static $internalServiceClass = "\OPNsense\XGuardGateway\XGuardGateway";
    protected static $internalServiceTemplate = "OPNsense/XGuardGateway";
    protected static $internalServiceEnabled = "general.Enabled";

    /**
     * The 'xguard/*' anchor is hooked into the ruleset by xguardgateway_firewall().
     * Changes only take effect once the filter is reloaded.
     */
    protected function invokeFirewallReload()
    {
        return true;
    }
}
