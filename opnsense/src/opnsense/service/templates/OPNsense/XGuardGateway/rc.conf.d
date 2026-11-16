{% if helpers.exists("OPNsense.xguardgateway.general.Enabled") and OPNsense.xguardgateway.general.Enabled == '1' %}
xguard_gateway_enable="YES"
{% else %}
xguard_gateway_enable="NO"
{% endif %}
