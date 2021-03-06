<?php
/*
 * Fez Devel
 * Univeristy of Queensland Library
 * Created by Matthew Smith on 29/11/2006
 * Extended by Lachlan Kuhn on 16/10/2007
 * This code is licensed under the GPL, see
 * http://www.gnu.org/copyleft/gpl.html
 * 
 */

$rootpath = dirname(dirname(__FILE__));
 
include_once "$rootpath/config.inc.php";
include_once(APP_INC_PATH.'class.sanity_checks.php');
include_once(APP_INC_PATH.'class.template.php');

$tpl = new Template_API();
$tpl->setTemplate('sanity_check.tpl.html');

$field = $_GET["field"];  // The request may be to check a specific config variable
$value = $_GET["value"];  // The request may be accompanied by a specific value to check
if (!empty($field)) {
    $tpl->assign("mode", "individual");
    $res = SanityChecks::runSpecificCheck($field, $value);
} else {
    $tpl->assign("mode", "all");
    $res = SanityChecks::runAllChecks();
}
$tpl->assign('sanity_results', $res);

$tpl->displayTemplate();
