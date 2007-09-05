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

include_once(APP_INC_PATH . "class.error_handler.php");
include_once(APP_INC_PATH . "class.misc.php");
include_once(APP_INC_PATH . "class.record.php");
include_once(APP_INC_PATH . "class.user.php");
include_once(APP_INC_PATH . "class.auth.php");


/**
 * Definitions of scripts that the workflow states can run.
 * This is just a mapping of scripts into the database with a few flags to say how they must be run
 */
class WF_Behaviour
{

    /**
     * Method used to get an associative array of action types.
     *
     * @access  public
     * @return  array The list of action types
     */
    function getTitles()
    {
        $stmt = "SELECT
                    wfb_id,
                    wfb_title
                 FROM
                    " . APP_TABLE_PREFIX . "wfbehaviour
                 ORDER BY
                    wfb_title ASC";
        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return array();
        } else {
            return $res;
        }
    }






    /**
     * Method used to remove a given list of custom fields.
     *
     * @access  public
     * @return  boolean
     */
    function remove()
    {
        global $HTTP_POST_VARS;

        $items = @implode(", ", $HTTP_POST_VARS["items"]);
        $stmt = "DELETE FROM
                    " . APP_TABLE_PREFIX . "wfbehaviour
                 WHERE
                    wfb_id IN (".$items.")";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return false;
        } 
    }


    /**
     * Insert a workflow behaviour
     *
     * @access  public
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    function insert($params = array())
    {
        if (empty($params)) {
        	$params = &$_POST;
        }
		
        $stmt = "INSERT INTO
                    " . APP_TABLE_PREFIX . "wfbehaviour
                 (
                    wfb_title,
                    wfb_version,
                    wfb_description,
                    wfb_script_name,
                    wfb_auto
                 ) VALUES (
                    '" . Misc::escapeString($params["wfb_title"]) . "',
                    '" . Misc::escapeString($params["wfb_version"]) . "',
                    '" . Misc::escapeString($params["wfb_description"]) . "',
                    '" . Misc::escapeString($params["wfb_script_name"]) . "',
                    '" . Misc::checkBox(@$params["wfb_auto"]) . "'
                 )";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        } else {
			return $GLOBALS["db_api"]->get_last_insert_id();
        }
    }

    /**
     * Update a workflow behaviour
     *
     * @access  public
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    function update($wfb_id, $params = array())
    {
        if (empty($params)) {
            $params = &$_POST;
        }
		
        $stmt = "UPDATE
                    " . APP_TABLE_PREFIX . "wfbehaviour
                 SET 
                    wfb_title = '" . Misc::escapeString($params["wfb_title"]) . "',
                    wfb_version = '" . Misc::escapeString($params["wfb_version"]) . "',
                    wfb_description = '" . Misc::escapeString($params["wfb_description"]) . "',
                    wfb_script_name = '" . Misc::escapeString($params["wfb_script_name"]) . "',
                    wfb_auto = '" . Misc::checkBox(@$params["wfb_auto"]) . "'
                 WHERE wfb_id = ".$wfb_id;
//		echo $stmt;
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        } else {
			//
        }
    }



    /**
     * get a list of workflow behaviours
     *
     * @access  public
     * @return  array The list of custom fields
     */
    function getList($wherestr='')
    {
        $stmt = "SELECT
                    *
                 FROM
                    " . APP_TABLE_PREFIX . "wfbehaviour wfb
                    ".$wherestr."
                 ORDER BY
                    wfb.wfb_title ASC";
        $res = $GLOBALS["db_api"]->dbh->getAll($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return array();
        } 
        return $res;
    }




    /**
     * get details of a workflow behaviour
     *
     * @access  public
     * @param   integer $wfb_id The workflow behaviour id
     * @return  array The workflow behaviour details
     */
    function getDetails($wfb_id)
    {
        $stmt = "SELECT
                    *
                 FROM
                    " . APP_TABLE_PREFIX . "wfbehaviour
                 WHERE
                    wfb_id=".$wfb_id;
        $res = $GLOBALS["db_api"]->dbh->getRow($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return array();
        } 
        return $res;
    }


    /**
     * get the list of automatic behaviours
     */
    function getListAuto()
    {
        return WF_Behaviour::getList(" WHERE wfb.wfb_auto='1' ");
    }

    /**
     * get the list of manual behaviours
     */
    function getListManual()
    {
        return WF_Behaviour::getList(" WHERE wfb.wfb_auto='0' ");
    }


    function exportBehaviours(&$bhs_elem, $wfb_ids)
    {
        $wfb_ids_str = Misc::arrayToSQL($wfb_ids);
        if (empty($wfb_ids_str)) {
        	return;
        }
        $behaviours = WF_Behaviour::getList(" where wfb_id IN ($wfb_ids_str) ");
        foreach ($behaviours as $behaviour) {
            $bh_elem = $bhs_elem->ownerDocument->createElement('WorkflowBehaviour');
            $bh_elem->setAttribute('wfb_id', $behaviour['wfb_id']);
            $bh_elem->setAttribute('wfb_title', $behaviour['wfb_title']);
            $bh_elem->setAttribute('wfb_description', $behaviour['wfb_description']);
            $bh_elem->setAttribute('wfb_version', $behaviour['wfb_version']);
            $bh_elem->setAttribute('wfb_script_name', $behaviour['wfb_script_name']);
            $bh_elem->setAttribute('wfb_auto', $behaviour['wfb_auto']);
            $bhs_elem->appendChild($bh_elem);
        }
    }

    function listXML($filename)
    {
        $doc = DOMDocument::load($filename);
        $xpath = new DOMXPath($doc);
        $xworkflows = $xpath->query('/workflows/WorkflowBehaviour');
        $list = array();
        foreach ($xworkflows as $xworkflow) {
            $xscript = $xworkflow->getAttribute('wfb_script_name');
            $item = array(
                'wfb_id' => $xworkflow->getAttribute('wfb_id'),
                'wfb_title' => $xworkflow->getAttribute('wfb_title'),
                'wfb_version' => $xworkflow->getAttribute('wfb_version'),
                );
            $elist = WF_Behaviour::getList($where="WHERE wfb_script_name='".$xscript."'");
            if (!empty($elist)) {
                $overwrite = true;
            } else {
                $overwrite = false;
            }
            $item['overwrite'] = $overwrite;   
            $item['overwrite_details'] = $elist[0]['wfb_title'].' '.$elist[0]['wfb_version'];   
            $list[] = $item;
        }
        return $list;
    }

	
    /**
	* Get the behaviours and map the exisiting DB id to the ids in the xml doc
    * If the behaviour script exists, then we map the XML id to the existing DB entry,
    * otherwise a new behaviour is created from the XML file and the new DB id is mapped 
    * @returns array $behaviour_ids_map
	*/
	function importBehaviours($doc, $wfb_ids, &$feedback)
	{
		$xpath = new DOMXPath($doc);
		$xbehaviours = $xpath->query('/workflows/WorkflowBehaviour');
        $behaviour_id_map = array();
		foreach ($xbehaviours as $xbehaviour) {
			$xid = $xbehaviour->getAttribute('wfb_id');
            if (!in_array($xid, $wfb_ids)) {
            	continue;
            }
            $xscript = $xbehaviour->getAttribute('wfb_script_name');
            $xtitle = $xbehaviour->getAttribute('wfb_title');
                $params = array(
                    'wfb_title' => $xbehaviour->getAttribute('wfb_title'),
                    'wfb_description' => $xbehaviour->getAttribute('wfb_description'),
                    'wfb_version' => $xbehaviour->getAttribute('wfb_version'),
                    'wfb_script_name' => $xbehaviour->getAttribute('wfb_script_name'),
                    'wfb_auto' => $xbehaviour->getAttribute('wfb_auto'),
                );
            	$elist = WF_Behaviour::getList($where="WHERE wfb_script_name='".$xscript."'");
                if (!empty($elist)) {
                    $feedback[] = "Overwriting behaviour ".$xtitle;
                    $dbid = $elist[0]['wfb_id'];
                    WF_Behaviour::update($dbid, $params);
                } else {
                    $feedback[] = "Importing new behaviour ".$xtitle;
                    $dbid = WF_Behaviour::insert($params);
                }
            
            $behaviour_id_map[$xid] = $dbid;
		}
        return $behaviour_id_map;
	}
	
	

}

// benchmarking the included file (aka setup time)
if (APP_BENCHMARK) {
    $GLOBALS['bench']->setMarker('Included Doc_Type_XSD Class');
}
?>
