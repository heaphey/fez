<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | Fez - Digital Repository System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2005, 2006, 2007, 2008 The University of Queensland,   |
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
// |          Lachlan Kuhn <l.kuhn@library.uq.edu.au                      |
// |          Rhys Palmer <r.palmer@library.uq.edu.au                     |
// |          Andrew Martlew <a.martlew@library.uq.edu.au>                |
// +----------------------------------------------------------------------+
//
//

/**
 * Class to handle Auth indexes
 *
 * @version 1.0
 * @author Christiaan Kortekaas <c.kortekaas@library.uq.edu.au>
 */

include_once(APP_INC_PATH . 'class.record.php');
include_once(APP_INC_PATH . "class.bgp_index_auth.php");
include_once(APP_INC_PATH . "class.filecache.php");

class AuthIndex
{
	var $get_auth_done_pids = array();
	var $bgp;
	var $pid_cache = array();
	var $pid_count = 0;
	var $cviews = array();

	function setIndexAuth($pid, $recurse=false)
	{
		$log = FezLog::get();


		$bgp = new BackgroundProcess_Index_Auth;
		$bgp->register(serialize(compact('pid','recurse')), Auth::getUserID());

	}

	function setBGP(&$bgp)
	{
		$this->bgp = &$bgp;
	}

	function setIndexAuthBGP($pid, $recurse = false, $topcall=true)
	{
		$log = FezLog::get();
		$db = DB_API::get();


		$this->bgp->setHeartbeat();
		$this->bgp->setProgress(++$this->pid_count);
		$dbtp = APP_TABLE_PREFIX;

		$res = Auth::getAuth($pid);

		$rows = array();
		$dupe_stopper = array();
		$values = array();
		$lister_values = array();
		$roles = Auth::getAllRoleIDs();
		$has_list_rules = false;
		$has_view_rules = false;


		// Check for datastream policy quick auth, if exists replace existing datastream policies with it
		$ds = Fedora_API::callGetDatastreams($pid);

		foreach ($ds as $dsTitle) {
			$dsIDName = $dsTitle['ID'];
			if ($dsTitle['controlGroup'] == "M"
				&& (!Misc::hasPrefix($dsIDName, 'preview_')
					&& !Misc::hasPrefix($dsIDName, 'web_')
					&& !Misc::hasPrefix($dsIDName, 'thumbnail_')
					&& !Misc::hasPrefix($dsIDName, 'stream_')
					&& !Misc::hasPrefix($dsIDName, 'presmd_'))) {
				Record::checkQuickAuthFezACML($pid, $dsIDName);
			}
		}

		// should not need this when going straight to fezacml xml rather than old rmf index
		if (!empty($res)) {
			// add some pre-processed special rules
			foreach ($res as $role => $rules) {

				if( $role == 'Lister' ) {

					foreach ( $rules as $ruleID => $rule ) {

						if( $rule['rule'] == "override" ) {
							unset($res[$role][$ruleID]);
							$has_list_rules = false;
							break;
						} elseif(  $rule['value'] != "off" ) {
							$has_list_rules = true;
						}

					}

				} elseif( $role == 'Viewer' ) {

					foreach ( $rules as $ruleID => $rule ) {

						if( $rule['rule'] == "override" ) {
							unset($res[$role][$ruleID]);
							$has_view_rules = false;
							break;
						} elseif( $rule['value'] != "off" ) {
							$has_view_rules = true;
						}

					}

				}
			}
		}

		// if no lister rules are found, then this pid is publically listable
		if (!$has_list_rules) {
			$res['Lister'] = array(array(
	            'rule' => 'public_list',
	            'value' => 1
			));
		}
		// if no viewer rules are found, then this pid is publically listable
		if (!$has_view_rules) {
			$res['Viewer'] = array(array(
	            'rule' => 'public_list',
	            'value' => 1
			));
		}

		// get the group ids
		$values_sql = array();
		$lister_values_sql = array();
		$loop = 0;
		foreach ($res as $role => $rules) {

			$arg_id = AuthRules::getOrCreateRuleGroup($rules,$topcall);
			$ukey = $pid."-".$role."-".$arg_id;

			if (!in_array($ukey, $dupe_stopper)) {
				$dupe_stopper[] = $ukey;
				if ($role == "Lister") {
					//$lister_values[$loop][] = $db->quote($pid);
					//$lister_values[$loop][] = $db->quote($arg_id, 'INTEGER');
					$lister_values[$loop][] = $pid;
					$lister_values[$loop][] = $arg_id;
					$lister_values_sql[] = '(?,?)';
				}

/*				$values[$loop][] = $db->quote($pid);
				$values[$loop][] = $db->quote($roles[$role], 'INTEGER');
				$values[$loop][] = $db->quote($arg_id, 'INTEGER'); */
				$values[$loop][] = $pid;
				$values[$loop][] = $roles[$role];
				$values[$loop][] = $arg_id;

				$values_sql[0] = '(?,?,?)';

				$rows[] = array(
                    'authi_pid'     => $pid,
                    'authi_role'    => $role,
                    'authi_arg_id'  => $arg_id
				);
			}

			$loop++;
		}

		// Only check for change of rules at top of recursion, otherwise it slows things down too much.
		if ($topcall) {

			// check if the auth rules have changed for this pid
			// - if they haven't then we don't need to recurse.
			$res = array();
			$stmt = "SELECT authi_pid, aro_role as authi_role, authi_arg_id FROM {$dbtp}auth_index2 i
                JOIN {$dbtp}auth_roles r ON r.aro_id = i.authi_role  WHERE authi_pid=?"; 
			try {
				$res = $db->fetchAll($stmt, array($pid));
			}
			catch(Exception $ex) {
				$log->err($ex);

				return -1;
			}

			$rules_changed = false;
			// check for added rules
			foreach ($res as $dbrow) {
				$found = false;
				foreach ($rows as $crow) {
					if ($crow['authi_role'] == $dbrow['authi_role']
					&& $crow['authi_arg_id'] == $dbrow['authi_arg_id']) {
						$found = true;
						break;
					}
				}
				if (!$found) {
					$rules_changed = true;
					break;
				}
			}

			if (!$rules_changed) {
				// check for deleted rules
				foreach ($rows as $crow) {
					$found = false;
					foreach ($res as $dbrow) {
						if ($crow['authi_role'] == $dbrow['authi_role']
						&& $crow['authi_arg_id'] == $dbrow['authi_arg_id']) {
							$found = true;
							break;
						}
					}
					if (!$found) {
						$rules_changed = true;
						break;
					}
				}
			}

		} else {
			// We are already recursing
			$rules_changed = true;
		}

		if ($rules_changed) {
			AuthIndex::clearIndexAuth($pid);

			if (is_numeric(strpos(APP_SQL_DBTYPE, "mysql"))) {
				$stmt = "INSERT IGNORE INTO ".$dbtp."auth_index2 (authi_pid,authi_role,authi_arg_id) VALUES ".implode(', ', $values_sql);
			}
			else {
				$stmt = "INSERT INTO ".$dbtp."auth_index2 (authi_pid,authi_role,authi_arg_id) VALUES ".implode(', ', $values_sql);
			}
			try {
				if(is_numeric(strpos(APP_SQL_DBTYPE, "mysql"))) {
					foreach($values as $value) {
						$db->query($stmt, $value);
					}
				}
				else {
					$stmt_delete = 'DELETE FROM '.$dbtp.'auth_index2 WHERE authi_pid=?';
					foreach($values as $value) {
						$db->query($stmt_delete, $value[0]);
						$db->query($stmt, $value);
					}
				}
			}
			catch(Exception $ex) {
				$log->err($ex);

				return -1;
			}

			if (is_numeric(strpos(APP_SQL_DBTYPE, "mysql"))) {
				$stmt = "INSERT IGNORE INTO ".$dbtp."auth_index2_lister (authi_pid,authi_arg_id) VALUES ".implode(', ', $lister_values_sql);
			}
			else {
				$stmt = "INSERT INTO ".$dbtp."auth_index2_lister (authi_pid,authi_arg_id) VALUES ".implode(', ', $lister_values_sql);
			}
			try {
				$lister_values = array_values($lister_values);
				if(is_numeric(strpos(APP_SQL_DBTYPE, "mysql"))) {
					$lister_values = Misc::array_flatten($lister_values, '', TRUE);
					$db->query($stmt, $lister_values);
				}
				else {
					$stmt_delete = 'DELETE FROM '.$dbtp.'auth_index2_lister WHERE authi_pid=?';
					foreach($lister_values as $lister_value) {
						$db->query($stmt_delete, $lister_value[0]);
						$db->query($stmt, $lister_value);
					}
				}
			}
			catch(Exception $ex) {
				$log->err($ex);

				return -1;
			}

			// get children and update their indexes.
			$rec = new RecordObject($pid);
			$children = $rec->getChildrenPids();
			$title = Record::getSearchKeyIndexValue($pid, "Title", false);
			if (!empty($children)) {
				$child_count = count($children);
				$this->bgp->setStatus("Recursing into ".$title." (".$child_count." child pids)");
			}

			foreach ($children as $child_pid) {
				$auth_index = new AuthIndex;
        		$auth_index->setBGP($this->bgp);
        		// Set topcall to false since we are now recursing to child records
            $topcall = false;
        		$auth_index->setIndexAuthBGP($child_pid, $recurse, $topcall);
			}

			if( APP_FILECACHE == "ON" ) {
				$cache = new fileCache($pid, 'pid='.$pid);
				$cache->poisonCache();

			}

			$this->bgp->setStatus("Finished Index Auth for ".$title);

			if( APP_SOLR_INDEXER == "ON" ) {
				// KJ/ETH: fulltext indexing of $pid should automatically
				// recurse to children
				FulltextQueue::singleton()->add($pid);
				FulltextQueue::singleton()->commit();
			}
		}

		if ($topcall) {
			$this->cleanIndex();
		}

		return 1;
	}

	public static function getIndexAuthRoles($pid)
	{
		$log = FezLog::get();


		$return = array();
		$db = DB_API::get();
		$dbtp = APP_TABLE_PREFIX;

		$usr_id = Auth::getUserID();
		if (!Auth::isAdministrator() && (is_numeric($usr_id))) {
			$stmt = "SELECT authi_role ".
                  "FROM {$dbtp}auth_index2 ".
                  "INNER JOIN {$dbtp}auth_rule_group_users ON authi_arg_id = argu_arg_id and argu_usr_id = ? ".
                  "WHERE authi_pid = ?";
			try {
				$res = $db->fetchCol($stmt, array($usr_id, $pid));
			}
			catch(Exception $ex) {
				$log->err($ex);

				return array();
			}
			$return = Auth::getIndexAuthCascade(array(array('rek_pid ' => $pid, 'authi_role' => $res)));
			$return = $return[0];
		} else {
			$return = Auth::getIndexAuthCascade(array(array('rek_pid ' => $pid)));
			$return = $return[0];
		}

		return $return;
	}

	function clearIndexAuth($pids)
	{
		$log = FezLog::get();
		$db = DB_API::get();


		if (empty($pids)) {

			return -1;
		} elseif (!is_array($pids)) {
			$pids = array($pids);
		}

		$pids = Misc::array_flatten($pids, '', true);
		$dbtp = APP_TABLE_PREFIX;
		$bind = Misc::arrayToSQLBindStr($pids);
		$stmt = "DELETE FROM ".$dbtp."auth_index2 WHERE authi_pid IN (".$bind.") ";
		try {
			$db->query($stmt, $pids);
		}
		catch(Exception $ex) {
			$log->err($ex);

			return -1;
		}

		$stmt = "DELETE FROM ".$dbtp."auth_index2_lister WHERE authi_pid IN (".$bind.") ";
		try {
			$db->query($stmt, $pids);
		}
		catch(Exception $ex) {
			$log->err($ex);

			return -1;
		}

		return 1;
	}

	function highestRuleGroup()
	{
		$log = FezLog::get();
		$db = DB_API::get();

		$res = null;

		$dbtp = APP_TABLE_PREFIX;
		$stmt = "SELECT max(arg_id) FROM ".$dbtp."auth_rule_groups";

		try {
			$res = $db->fetchOne($stmt);
		}
		catch(Exception $ex) {
			$log->err($ex);

			return -1;
		}

		return $res;
	}

	/**
	 *  If there are too many rules in the index that are not used anywhere then delete them.
	 */
	function cleanIndex()
	{
		$log = FezLog::get();
		$db = DB_API::get();


		// check for unused rules
		$dbtp = APP_TABLE_PREFIX;
		$stmt = "select count(*) from ".$dbtp."auth_rule_groups where not exists (
            select * FROM ".$dbtp."auth_index2 where authi_arg_id=arg_id)";
		$res = null;
		try {
			$res = $db->fetchOne($stmt);
		}
		catch(Exception $ex) {
			$log->err($ex);

			return;
		}


		if ($res > 1000) {
			// found a lot of unused rules so lets get rid of them
			$stmt = "delete from ".$dbtp."auth_rule_groups where not exists (
                select * FROM ".$dbtp."auth_index2 where authi_arg_id=arg_id)";
			try {
				$db->query($stmt);
			}
			catch(Exception $ex) {
				$log->err($ex);
			}
			$stmt = "delete from ".$dbtp."auth_rule_group_rules where not exists (
                select * FROM ".$dbtp."auth_rule_groups where argr_arg_id=arg_id)";
			try {
				$db->query($stmt);
			}
			catch(Exception $ex) {
				$log->err($ex);
			}
			$stmt = "delete from ".$dbtp."auth_rules where not exists (
                select * FROM ".$dbtp."auth_rule_group_rules where argr_ar_id=ar_id)";
			try {
				$db->query($stmt);
			}
			catch(Exception $ex) {
				$log->err($ex);
			}
		}

	}
}
