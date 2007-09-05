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
if (!is_file("config.inc.php")) {
    header("Location: setup/");
    exit;
}
include_once("config.inc.php");
if (!defined('APP_INC_PATH')) {
    header("Location: setup/");
    exit;
}

include_once(APP_INC_PATH . "db_access.php");
include_once(APP_INC_PATH . "class.auth.php");
include_once(APP_INC_PATH . "class.user.php");
include_once(APP_INC_PATH . "class.collection.php");
include_once(APP_INC_PATH . "class.news.php");
include_once(APP_INC_PATH . "class.survey.php");
include_once(APP_INC_PATH . "class.template.php");
include_once(APP_INC_PATH . "class.validation.php");
include_once(APP_INC_PATH . "najax/najax.php");
include_once(APP_INC_PATH . "najax_objects/class.suggestor.php");

// Redirect if sent from an alias or IP as shibboleth and sessions won't like it otherwise
if ($_SERVER['HTTP_HOST'] != APP_HOSTNAME)  {
	   header ("HTTP 302 Redirect");
       header ("Location: http://".APP_HOSTNAME);
}

NAJAX_Server::allowClasses('Suggestor');
if (NAJAX_Server::runServer()) {
	exit;
}
if (@$_SESSION['IDP_LOGIN_FLAG'] == 1) {
	Auth::GetShibAttributes();
	$_SESSION['IDP_LOGIN_FLAG'] = 0;
}
if (@$_SESSION[APP_SHIB_ATTRIBUTES_SESSION]['Shib-Attributes'] != "") {
// Uncomment this to see a debug output of all the shibboleth attributes in the session
/*	echo "<pre>";
	print_r($_SESSION[APP_SHIB_ATTRIBUTES_SESSION]);
	echo "</pre>";  */

	if (Auth::LoginAuthenticatedUser("", "", true) > 0) {
    	Auth::redirect(APP_RELATIVE_URL . "login.php?err=22");
	}
	if ((@$_SESSION[APP_SHIB_ATTRIBUTES_SESSION]['Shib-Attributes'] != "") && (SHIB_SURVEY == "ON")) {
//	  if ((!Survey::hasFilledSurvey(Auth::getUserID()) == 1) && (User::getShibLoginCount(Auth::getUserID()) > 1)) { //if they are shib user and they have logged in at least once before send them to the survey
	  if (!Survey::hasFilledSurvey(Auth::getUserID()) == 1) { //send them to the survey the first time they login
		  Auth::redirect(APP_RELATIVE_URL . "survey.php");
	  }
	}	
	if (!empty($_SESSION["url"])) { 
		$url = $_SESSION["url"];
		$_SESSION["url"] = "";
		Auth::redirect($url);			
		exit;
	}
} elseif (count($HTTP_POST_VARS) > 0) {
	if (Validation::isWhitespace($HTTP_POST_VARS["username"])) {
		Auth::redirect(APP_RELATIVE_URL . "login.php?err=1");
	}
	if (Validation::isWhitespace($HTTP_POST_VARS["passwd"])) {
		Auth::redirect(APP_RELATIVE_URL . "login.php?err=2&username=" . $HTTP_POST_VARS["username"]);
	}
    if (!Auth::isActiveUser($HTTP_POST_VARS['username'])) {
        Auth::redirect(APP_RELATIVE_URL . "login.php?err=7&username=" . $HTTP_POST_VARS["username"]);
    }
	// check if the password matches
	if (!Auth::isCorrectPassword($HTTP_POST_VARS["username"], $HTTP_POST_VARS["passwd"])) {
		Auth::redirect(APP_RELATIVE_URL . "login.php?err=3&username=" . $HTTP_POST_VARS["username"]);
	}
    $loginres = Auth::LoginAuthenticatedUser($HTTP_POST_VARS["username"], $HTTP_POST_VARS["passwd"]);
    if ($loginres > 0) {
        Auth::redirect(APP_RELATIVE_URL . "login.php?err={$loginres}&username=" . $HTTP_POST_VARS["username"]);	
    } 	
	if (!empty($HTTP_POST_VARS["url"])) {
		Auth::redirect(urldecode($HTTP_POST_VARS["url"])); 
	} else {
//		Auth::redirect(APP_RELATIVE_URL); // even though its the same page redirect so if they refresh it doesnt have the post vars
		Auth::redirect(APP_BASE_URL); // even though its the same page redirect so if they refresh it doesnt have the post vars
		$extra = '';
	}
}

$tpl = new Template_API();
$tpl->setTemplate("front_page.tpl.html");
//$tpl->setTemplate("maintenance.tpl.html");

$username = Auth::getUsername();
$tpl->assign("isUser", $username);
if (Auth::userExists($username)) { // if the user is registered as a Fez user
	$tpl->assign("isFezUser", $username);
}
$isAdministrator = User::isUserAdministrator($username);
$tpl->assign("isAdministrator", $isAdministrator);
// get the 5 most recently added items this week
$tpl->assign("today", date("Y-m-d"));
$tpl->assign("today_day_name", date("l"));
$tpl->assign("yesterday", date("Y-m-d", time()-86400));
$tpl->assign("last", "Last ");

$list = array();
//$list = Collection::browseListing(0, 5, "Created Date", $sort_by, 0);
$options = array();
$options["sort_order"] = "1";
$sort_by = "searchKey".Search_Key::getID("Created Date");
$options["searchKey".Search_Key::getID("Status")] = 2; // enforce published records only
$list = Record::getListing($options, $approved_roles=array("Lister"), 0,5, "Created Date");
$tpl->assign("thisYear", date("Y"));
$tpl->assign("lastYear", date("Y") - 1);
$list = $list["list"];
//$list=array();
$tpl->assign("list", $list);
$tpl->assign("eserv_url", APP_RELATIVE_URL."eserv.php");
$news = News::getList(5);       // Maximum of 5 news posts for front page.
$news_count = count($news);
$tpl->assign("news", $news);
$tpl->assign("isHomePage", "true");
$tpl->assign("news_count", $news_count);
$tpl->headerscript .= "window.oTextbox_front_search
	= new AutoSuggestControl(document.search_frm, 'front_search', document.getElementById('front_search'), document.getElementById('front_search'),
			new StateSuggestions('Collection','suggest',false,
				'class.collection.php'));
	";


$tpl->assign('najax_header', NAJAX_Utilities::header(APP_RELATIVE_URL.'include/najax'));
$tpl->registerNajax(NAJAX_Client::register('Suggestor', 'index.php'));
$tpl->displayTemplate();
//echo ($GLOBALS['bench']->getOutput());
?>
