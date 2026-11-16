<?php
function xguardgateway_services()
{
    global $config;

    $services = [];

    $pidfile = (string) (new OPNsense\XGuardGateway\XGuardGateway())->general->PidFile;

    if (isset($config['OPNsense']['xguardgateway']['general']['Enabled']) && $config['OPNsense']['xguardgateway']['general']['Enabled'] == 1) {
        $services[] = [
            "description" => "XGuard Gateway",
            "configd" => [
                "start" => ["xguardgateway start"],
                "restart" => ["xguardgateway restart"],
                "stop" => ["xguardgateway stop"],
            ],
            "pidfile" => empty($pidfile) ? "/var/run/xguard_gateway.pid" : $pidfile,
            "name" => "xguardgateway",
        ];
    }

    return $services;
}

function xguardgateway_interfaces()
{
    $interfaces = [];

    $interfaces["xguard"] = [
        "descr" => gettext("XGuard (Group)"),
        "if" => "xguard",
        "virtual" => true,
        "enable" => true,
        "type" => "group",
        "networks" => [],
    ];

    return $interfaces;
}

function xguardgateway_devices()
{
    $interface = (new OPNsense\XGuardGateway\XGuardGateway())->general
        ->IfName;
    $interface = empty((string) $interface) ? 'wg0' : (string) $interface;

    $devices[] = [
        "configurable" => false,
        "pattern" => sprintf("^%s$", preg_quote($interface, '/')),
        "type" => "wireguard",
        "volatile" => true,
        "names" => [
            $interface => [
                "descr" => sprintf(
                    "%s (XGuard Gateway)",
                    $interface
                ),
                "ifdescr" => "WireGuard interface used by XGuard Gateway",
                "name" => $interface,
            ],
        ],
    ];

    return $devices;
}

function xguardgateway_enabled()
{
    global $config;

    return isset($config['OPNsense']['xguardgateway']['general']['Enabled']) &&
    $config['OPNsense']['xguardgateway']['general']['Enabled'] == 1;
}

function xguardgateway_firewall($fw)
{
    if (!xguardgateway_enabled()) {
        return;
    }

    // $fw->registerAnchor('xguard/*', 'nat', 1, 'head');
    // $fw->registerAnchor('xguard/*', 'rdr', 1, 'head');
    // IMPORTANT: never register this anchor as 'quick'. On FreeBSD 15+
    // (OPNsense 26.7+), a 'quick' anchor short-circuits the parent ruleset
    // even when no inner rule matches, silently skipping OPNsense's own
    // firewall rules.
    $model = new OPNsense\XGuardGateway\XGuardGateway();
    $placement = (string) $model->general->FwAnchorPlacement ?: 'tail';
    $quick = (string) $model->general->FwAnchorQuick === '1';
    $fw->registerAnchor('xguard/*', 'fw', 1, $placement, $quick);
}
