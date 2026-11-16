<h2>Configuration</h2>

<script type="text/javascript">
$( document ).ready(function() {
    mapDataToFormUI({"frm_GeneralSettings": "/api/xguardgateway/settings/get"}).done(function(data) {
    	updateServiceControlUI("xguardgateway");
    });

    $("#saveAct").click(function(){
        $("#responseMsg").removeClass("hidden");
        saveFormToEndpoint(url="/api/xguardgateway/settings/set", formid='frm_GeneralSettings', callback_ok=function() {
            updateServiceControlUI("xguardgateway");
    		ajaxCall(url="/api/xguardgateway/service/reconfigure", sendData={}, callback=function(data, status) {
    			$("#responseMsg").html(data["status"]);
                if (status !== "success" || data["status"] !== "ok") {
                    return;
                }

                ajaxCall(url="/api/xguardgateway/service/restart", sendData={}, callback=function(data, status) {
                    $("#responseMsg").html(data['status']);
                    updateServiceControlUI("xguardgateway");
                });
            });
        });
    });

    $("#startAct").click(function () {
        stdDialogConfirm(
            '{{ lang._("Confirm gateway (re)start") }}',
            '{{ lang._("Do you want to (re)start XGuard Gateway?") }}',
            '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}', function () {
                $("#startAct").addClass("fa fa-spinner");
				$("#responseMsg").removeClass("hidden");
                ajaxCall(url="/api/xguardgateway/service/restart", sendData={}, callback=function(data, status) {
                    $("#startAct").removeClass("fa fa-spinner fa-pulse");
    				$("#responseMsg").html(data['status']);
    				updateServiceControlUI("xguardgateway");
            });
        });
    });

    $("#stopAct").click(function () {
        stdDialogConfirm(
            '{{ lang._("Confirm gateway stop") }}',
            '{{ lang._("Do you want to stop XGuard Gateway?") }}',
            '{{ lang._("Yes") }}', '{{ lang._("Cancel") }}', function () {
                $("#stopAct").addClass("fa fa-spinner");
                $("#responseMsg").removeClass("hidden");
                ajaxCall(url="/api/xguardgateway/service/stop", sendData={}, callback=function(data, status) {
                    $("#stopAct").removeClass("fa fa-spinner fa-pulse");
                    $("#responseMsg").html(data['status']);
                    updateServiceControlUI("xguardgateway");
                });
        });
    });
});
</script>
<div class="alert alert-info hidden" role="alert" id="responseMsg">
</div>

<div class="col-md-12">
    {{ partial("layout_partials/base_form", ['fields':generalForm,'id':'frm_GeneralSettings']) }}
</div>

<div class="col-md-12">
	<button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
	<button class="btn btn-primary" id="startAct" type="button"><b>{{ lang._('Start/Restart') }}</b></button>
	<button class="btn btn-default" id="stopAct" type="button"><b>{{ lang._('Stop') }}</b></button>
</div>
