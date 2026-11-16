<?php
namespace OPNsense\XGuardGateway;
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick("OPNsense/XGuardGateway/index");
        $this->view->generalForm = $this->getForm("general");
    }
}
