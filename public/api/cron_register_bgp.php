$bgp = new BackgroundProcess();
$bgp->register(array(), Auth::getUserID());
<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | Fez - Digital Repository System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2005, 2006, 2007 The University of Queensland,         |
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
// | Authors: Aaron Brown <a.brown@library.uq.edu.au>                     |
// +----------------------------------------------------------------------+
//
include_once('../config.inc.php');
include_once(APP_INC_PATH . "class.background_process.php");

$callback = $_GET['callback'];
$callback = !empty($callback) ? preg_replace('/[^a-z0-9\.$_]/si', '', $callback) : false;
header('Access-Control-Allow-Origin: *');
header('Content-Type: ' . ($callback ? 'application/javascript' : 'application/json') . ';charset=UTF-8');

echo ($callback ? '/**/'.$callback . '(' : '');

$response = -1;
$error = '';
$file = APP_INC_PATH . 'class.' . preg_replace('/[^a-z0-9__]/si', '', $_GET['file']) . '.php';
$class = preg_replace('/[^a-z0-9_]/si', '', $_GET['class']);
$allowedBgps = [
  'BackgroundProcess_Run_Integrity_Checks'
];

if ($_GET['token'] !== $_SERVER["APPLICATION_WEBCRON_TOKEN"]) {
  $error = 'Invalid token';
}
else if (! in_array($class, $allowedBgps)) {
  $error = 'Invalid BackgroundProcess subclass';
}
else if (file_exists($file)) {
  include_once($file);
  $bgp = new $class;
  if (is_subclass_of($bgp, 'BackgroundProcess')) {
    $response = $bgp->register(serialize($_GET['input']), User::getUserIDByUsername('webcron'));
    if ($response === -1) {
      $error = 'Failed to register background process';
    }
  } else {
    $error = 'Not a subclass of BackgroundProcess';
  }
} else {
  $error = 'Background process class file not found';
}

if ($response !== -1) {
  echo json_encode(["status" => "ok", "bgp_id" => $response]);
} else {
  http_response_code(400);
  echo json_encode(["status" => "fail", "message" => $error]);
}

echo $callback ? ');' : '';