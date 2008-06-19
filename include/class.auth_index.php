<?php

include_once(APP_INC_PATH.'class.record.php');
include_once(APP_INC_PATH . "class.bgp_index_auth.php");

class AuthIndex {
    var $get_auth_done_pids = array();
    var $bgp;
    var $pid_cache = array();
    var $pid_count = 0;

    function setIndexAuth($pid)
    {
       $bgp = new BackgroundProcess_Index_Auth; 
       $bgp->register(serialize(compact('pid','recurse')), Auth::getUserID());
    }

    function setBGP(&$bgp)
    {
        $this->bgp = &$bgp;
    }

    function setIndexAuthBGP($pid, $recurse = false, $topcall=true)
    {
        $this->bgp->setHeartbeat();
        $this->bgp->setProgress(++$this->pid_count);
        $dbtp = APP_TABLE_PREFIX;
        // topcall means this is the first call and not a recursion.  We want to clear all our caches at the
        // start but then use them as we recurse.
        if ($topcall) {
            // clear the parent cache
            Record::getParents($pid, true);
        }
        $res = Auth::getAuth($pid);
//		Error_Handler::logError($res, __FILE__, __LINE__);
//		print_r($res); //exit;
//        $res = AuthIndex::getIndexAuth($pid,$topcall);
        $rows = array();
        $dupe_stopper = array();
        $values = "";
        $lister_values = "";
        $roles = Auth::getAllRoleIDs();
        $has_list_rules = false;
        $has_view_rules = false;
// should not need this when going straight to fezacml xml rather than old rmf index
        if (!empty($res)) {
            // add some pre-processed special rules
            foreach ($res as $source_pid => $groups) {
                foreach ($groups as $role => $group) {
                    foreach ($group as $row) {
                        // check for rules on listing to determine if this pid is public or not
//                        if ($row['role'] == $roles['Lister'] && $row['value'] != "off") {
                        if ($row['role'] == 'Lister' && $row['value'] != "off") {
                            $has_list_rules = true;
                        }
                        // check for rules on viewing to determine if this pid is public or not
                        if ($row['role'] == 'Viewer' && $row['value'] != "off") {
                            $has_view_rules = true;
                        }
                    }
                }
            }
        } 
        // if no lister rules are found, then this pid is publically listable
        if (!$has_list_rules) {
            $res[$pid]['Lister'][] = array(
	            'pid' => $pid, 
	            'role' => $roles['Lister'], 
	            'rule' => 'public_list', 
	            'value' => 1
            );
        }
        // if no viewer rules are found, then this pid is publically listable
        if (!$has_view_rules) {
            $res[$pid]['Viewer'][] = array(
	            'pid' => $pid, 
	            'role' => $roles['Viewer'], 
	            'rule' => 'public_list', 
	            'value' => 1
            );
        }
        
        // get the group ids
        foreach ($res as $groups) {
            foreach ($groups as $role => $group) {
            	$arg_id = AuthRules::getOrCreateRuleGroup($group,$topcall);
            	$ukey = $pid."-".$role."-".$arg_id;
	           	if (!in_array($ukey, $dupe_stopper)) {
            		$dupe_stopper[] = $ukey;
					if ($role == "Lister") {
	                	$lister_values .= "('".$pid."', ".$arg_id."),";
					}
	                $values .= "('".$pid."', ".$roles[$role].", ".$arg_id."),";
	                $rows[] = array('authi_pid' => $pid, 'authi_role' => $role, 'authi_arg_id' => $arg_id);
            	}
            }
        }
        $values = rtrim($values,', ');
        $lister_values = rtrim($lister_values,', ');
        // Only check for change of rules at top of recursion, otherwise it slows things down too much.
        if ($topcall) {
            // check if the auth rules have changed for this pid - if they haven't then we don't need to recurse.
            $stmt = "SELECT * FROM ".$dbtp."auth_index2 WHERE authi_pid='".$pid."' ";
            $res = $GLOBALS["db_api"]->dbh->getAll($stmt, DB_FETCHMODE_ASSOC);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
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
            $stmt = "INSERT INTO ".$dbtp."auth_index2 (authi_pid,authi_role,authi_arg_id) VALUES ".$values." ";
            $res = $GLOBALS["db_api"]->dbh->query($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
                return -1;
            }
			// now update the cut down speedier lister only auth index
            $stmt = "INSERT INTO ".$dbtp."auth_index2_lister (authi_pid,authi_arg_id) VALUES ".$lister_values." ";
            $res = $GLOBALS["db_api"]->dbh->query($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
                return -1;
            }
            
            
            // get children and update their indexes.
            $rec = new RecordGeneral($pid);
            $children = $rec->getChildrenPids();
			$title = Record::getSearchKeyIndexValue($pid, "Title", false);
            if (!empty($children)) {
				$child_count = count($children);
                $this->bgp->setStatus("Recursing into ".$title." (".$child_count." child pids)");
            }
            foreach ($children as $child_pid) {
                AuthIndex::setIndexAuthBGP($child_pid, $recurse, false);
                
                if( APP_SOLR_INDEXER == "ON" ) {
                    // KJ/ETH: fulltext indexing of $pid should automatically
                    // recurse to children                
                	FulltextQueue::singleton()->add($child_pid);
                }
            }
            
            $this->bgp->setStatus("Finished Index Auth for ".$title);
        }
        
        if ($topcall) {
            $this->cleanIndex();
        }
        return 1;
    }


	function getIndexAuthRoles($pid) {
		$return = array();
       	$dbtp = APP_TABLE_PREFIX;
		$usr_id = Auth::getUserID();
		if (!Auth::isAdministrator() && (is_numeric($usr_id))) {
          $stmt = "SELECT
                       authi_role
                     FROM ";
    
          	$stmt .=     $dbtp . "auth_index2 inner join " . 
                        $dbtp . "auth_rule_group_users ON authi_arg_id = argu_arg_id and argu_usr_id = ".$usr_id.
                       "  WHERE authi_pid = '".$pid."'";
            $res = $GLOBALS["db_api"]->dbh->getCol($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
                return array();
            } else {
    			$return = Auth::getIndexAuthCascade(array(array('rek_pid ' => $rek_pid, 'authi_role' => $res)));
    			$return = $return[0];
                return $return;
    
            }
        } else {
    		$return = Auth::getIndexAuthCascade(array(array('rek_pid ' => $rek_pid)));
    		$return = $return[0];
    		return $return;
    	}
    
	}

    function clearIndexAuth($pids)
    {
        if (empty($pids)) {
            return -1;
        } elseif (!is_array($pids)) {
            $pids = array($pids);
        }
        $pids_str = Misc::arrayToSQL($pids);
        $dbtp = APP_TABLE_PREFIX;
        $stmt = "DELETE FROM ".$dbtp."auth_index2 WHERE authi_pid IN (".$pids_str.") ";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        }	
        $stmt = "DELETE FROM ".$dbtp."auth_index2_lister WHERE authi_pid IN (".$pids_str.") ";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        }	
        return 1;
    }

    function highestRuleGroup()
    {
        $dbtp = APP_TABLE_PREFIX;
        $stmt = "SELECT max(arg_id) FROM ".$dbtp."auth_rule_groups";
        $res = $GLOBALS["db_api"]->dbh->getOne($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        }
        return $res;
    }

    /**
     *  If there are too many rules in the index that are not used anywhere then delete them.
     */
    function cleanIndex()
    {
        // check for unused rules
        $dbtp = APP_TABLE_PREFIX;
        $stmt = "select count(*) from ".$dbtp."auth_rule_groups where not exists (
            select * FROM ".$dbtp."auth_index2 where authi_arg_id=arg_id)";
        $res = $GLOBALS["db_api"]->dbh->getOne($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            $res = 0;
        }
        if ($res > 1000) {
            // found a lot of unused rules so lets get rid of them
            $stmt = "delete from ".$dbtp."auth_rule_groups where not exists (
                select * FROM ".$dbtp."auth_index2 where authi_arg_id=arg_id)";
            $res = $GLOBALS["db_api"]->dbh->query($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            }
            $stmt = "delete from ".$dbtp."auth_rule_group_rules where not exists (
                select * FROM ".$dbtp."auth_rule_groups where argr_arg_id=arg_id)";
            $res = $GLOBALS["db_api"]->dbh->query($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            }
            $stmt = "delete from ".$dbtp."auth_rules where not exists (
                select * FROM ".$dbtp."auth_rule_group_rules where argr_ar_id=ar_id)";
            $res = $GLOBALS["db_api"]->dbh->query($stmt);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            }
        }
     }
}


?>
