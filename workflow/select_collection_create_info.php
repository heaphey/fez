<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | Fez - Digital Repository System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2005, 2006 The University of Queensland,               |
// | Australian Partnership for Sustainable Repositories,                 |
// | eScholarship Project                                                 |
// |                                                                      |
// | Some of the Fez code was derived from Eventum (Copyright 2003, 2004  |
// | MySQL AB - http://dev.mysql.com/downloads/other/eventum/ - GPL)      |
// |                                                                      |
// | This program is free software; you can redistribute it and/or modify |
// | it under the terms of the GNU General Public License as published by |
// | the Free Software Foundation; either version 2 of the License, or    |
// | (at your option) any later version.                                  |
// |                                                                      |
// | This program is distributed in the hope that it will be useful,      |
// | but WITHOUT ANY WARRANTY; without even the implied warranty of       |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        |
// | GNU General Public License for more details.                         |
// |                                                                      |
// | You should have received a copy of the GNU General Public License    |
// | along with this program; if not, write to:                           |
// |                                                                      |
// | Free Software Foundation, Inc.                                       |
// | 59 Temple Place - Suite 330                                          |
// | Boston, MA 02111-1307, USA.                                          |
// +----------------------------------------------------------------------+
// | Authors: Christiaan Kortekaas <c.kortekaas@library.uq.edu.au>,       |
// |          Matthew Smith <m.smith@library.uq.edu.au>                   |
// +----------------------------------------------------------------------+
//
//
include_once("../config.inc.php");

include_once(APP_INC_PATH . "class.template.php");
include_once(APP_INC_PATH . "class.auth.php");
include_once(APP_INC_PATH . "class.user.php");
include_once(APP_INC_PATH . "class.record.php");
include_once(APP_INC_PATH . "class.misc.php");
include_once(APP_INC_PATH . "class.setup.php");
include_once(APP_INC_PATH . "db_access.php");
include_once(APP_INC_PATH . "class.collection.php");
include_once(APP_INC_PATH . "class.community.php");
include_once(APP_INC_PATH . "class.date.php");
include_once(APP_INC_PATH . "class.doc_type_xsd.php");
include_once(APP_INC_PATH . "class.workflow_trigger.php");
include_once(APP_INC_PATH . "class.fedora_api.php");
include_once(APP_INC_PATH . "class.xsd_html_match.php");
include_once(APP_INC_PATH . "najax_classes.php");


$tpl = new Template_API();
$tpl->setTemplate("workflow/index.tpl.html");
$tpl->assign("type", "select_collection_create_info");
$tpl->assign("type_name", "Select Community");

Auth::checkAuthentication(APP_SESSION);
$isUser = Auth::getUsername();
$tpl->assign("isUser", $isUser);
$isAdministrator = User::isUserAdministrator($isUser);
$tpl->assign("isAdministrator", $isAdministrator);
$wfstatus = &WorkflowStatusStatic::getSession(); // restores WorkflowStatus object from the session

$wfstatus->setTemplateVars($tpl);
$cat = Misc::GETorPOST('cat');
if ($cat == 'submit') {
    $wfstatus->pid = Misc::GETorPOST('community_pid');
    $wfstatus->xdis_id = Misc::GETorPOST('xdis_id');
    $wfstatus->parent_pid = Misc::GETorPOST('-1');
}
$wfstatus->checkStateChange();

// LUR: get the communities where the user is allowed to create collections
/*$communities = Community::getList(0, 150);
$index=0;
foreach ($communities['list'] as $item) {
	if ($item['isCreator'] != 1)
	{
		array_splice($communities['list'], $index,1);
	}
	else {
		$index++;
	}
}
$communities_list = array();
if (sizeof($communities['list']) > 0)
{
	$communities_list = Misc::keyPairs($communities['list'], 'rek_pid', 'rek_title');
	$communities_list = Misc::stripOneElementArrays($communities_list);
}
*/
$communities_list = Community::getCreatorListAssoc();
$tpl->assign('communities_list', $communities_list);
$tpl->assign('communities_list_selected', $communities_list['rek_pid']);
$tpl->registerNajax( NAJAX_Client::register('SelectCreateInfo', APP_RELATIVE_URL.'ajax.php'));

$tpl->displayTemplate();
?>
