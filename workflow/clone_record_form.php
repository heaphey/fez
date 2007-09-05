<?php
/*
 * Fez
 * Univeristy of Queensland Library
 * Created by Matthew Smith on 27/03/2007
 * This code is licensed under the GPL, see
 * http://www.gnu.org/copyleft/gpl.html
 * 
 */
include_once("../config.inc.php");
include_once(APP_INC_PATH . "class.template.php");
 
$tpl = new Template_API();
$tpl->setTemplate("workflow/index.tpl.html");
$tpl->assign("type", 'clone_record_form');

Auth::checkAuthentication(APP_SESSION);
$tpl->setAuthVars();

$wfstatus = &WorkflowStatusStatic::getSession(); // restores WorkflowStatus object from the session
$pid = $wfstatus->pid;
$tpl->assign("pid", $pid);
$wfstatus->setTemplateVars($tpl);
if (@$_REQUEST["cat"] == "submit") {
    $new_xdis_id = $_REQUEST['new_xdis_id'];
    $wfstatus->assign('new_xdis_id', $new_xdis_id);
    $is_succession = $_REQUEST['is_succession'];
    $wfstatus->assign('is_succession', $is_succession);
    $wfstatus->assign('clone_attached_datastreams', $_REQUEST['clone_attached_datastreams']);
    $wfstatus->assign('collection_pid', $_REQUEST['collection_pid']);
}
$wfstatus->checkStateChange();

$xdis_list = XSD_Display::getAssocListDocTypes();
$record = new RecordGeneral($pid);
$xdis_id = $record->getXmlDisplayId();

$tpl->assign(compact('xdis_id','xdis_list'));

$parents = $record->getParents();
$collection_pid = '';
$collection_title = '';
foreach ($parents as $parent) {
    $col = new RecordGeneral($parent);
    if ($col->canCreate()) {
        $collection_pid = $parent;
        //$collection_title = $parent['title'][0]; //old way - if we really need the title we will need to look it up..
        break;
    }
}
$tpl->assign(compact('collection_pid','collection_title'));

$js = <<<EOT
window.oTextbox_xsd_display_fields_6346_1_lookup
                        = new AutoSuggestControl(document.wfl_form1, 'collection_id', null, document.getElementById('record_search'),
                                new StateSuggestions('Collection','suggestCreateList', false,'class.collection.php'),
                                'cloneSuggestorCallback');
EOT;

$tpl->onload($js); 
$tpl->registerNajax(NAJAX_Client::register('Suggestor', APP_RELATIVE_URL.'ajax.php'));

 
$tpl->displayTemplate(); 
?>