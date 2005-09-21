<?php
/* vim: set expandtab tabstop=4 shiftwidth=4: */
// +----------------------------------------------------------------------+
// | Fez - Digital Repository                                          |
// +----------------------------------------------------------------------+
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
// |																	  |
// | Some code and structure is derived from Eventum (GNU GPL - MySQL AB) |
// | http://dev.mysql.com/downloads/other/eventum/index.html			  |
// | Eventum is primarily authored by Jo�o Prado Maia <jpm@mysql.com>     |
// +----------------------------------------------------------------------+
// | Authors: Christiaan Kortekaas <c.kortekaas@library.uq.edu.au>        |
// |          Matthew Smith <m.smith@library.uq.edu.au>                   |
// +----------------------------------------------------------------------+
//
//

/**
 * Class to handle controlled vocabularies.
 *
 * @version 1.0
 * @author Christiaan Kortekaas <c.kortekaas@library.uq.edu.au>
 * @author Matthew Smith <m.smith@library.uq.edu.au>
 */

include_once(APP_INC_PATH . "class.error_handler.php");
include_once(APP_INC_PATH . "class.misc.php");
include_once(APP_INC_PATH . "class.record.php");
include_once(APP_INC_PATH . "class.user.php");
include_once(APP_INC_PATH . "class.auth.php");


class Controlled_Vocab
{

    /**
     * Method used to remove a given list of controlled vocabularies.
     *
     * @access  public
     * @return  boolean
     */
    function remove()
    {
        global $HTTP_POST_VARS;
		// first delete all children
		// get all immediate children


        $items = $HTTP_POST_VARS["items"];
		if (!is_array($items)) { return false; }
		$all_items = $items;
		foreach ($items as $item) {
			$child_items = Controlled_Vocab::getAllTreeIDs($item);
			if (is_array($child_items)) {
				$all_items = array_merge($all_items, $child_items);
			}
		}
        $all_items = ltrim(Controlled_Vocab::implode_r(", ", $all_items), ", ");
        $stmt = "DELETE FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 WHERE
                    cvo_id IN ($all_items)";
		Controlled_Vocab::deleteRelationship($all_items);
//		echo $stmt;
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return false;
        } else {
		  return true;
        }
    }
	function implode_r ($glue, $pieces){
		$out = "";
		foreach ($pieces as $piece) {
			if (is_array ($piece)) {
				$out .= Controlled_Vocab::implode_r($glue, $piece); // recurse
			} else {
				$out .= $glue.$piece;
			}
		}	 
		return $out;
	}
	function deleteRelationship($items) {
        $stmt = "DELETE FROM 
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship
                 WHERE
                    cvr_parent_cvo_id IN ($items) OR cvr_child_cvo_id IN ($items)";

        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return false;
        } else {
		  return true;
        }
	
	}

    /**
     * Method used to add a new controlled vocabulary to the system.
     *
     * @access  public
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    function insert()
    {
        global $HTTP_POST_VARS;
		
        $stmt = "INSERT INTO
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 (
                    cvo_title
                 ) VALUES (
                    '" . Misc::escapeString($HTTP_POST_VARS["cvo_title"]) . "'
                 )";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        } else {
			// get last db entered id
			$new_id = $GLOBALS["db_api"]->get_last_insert_id();
			Controlled_Vocab::associateParent($HTTP_POST_VARS["parent_id"], $new_id);

			return 1;
        }
    }


    /**
     * Method used to add a new controlled vocabulary to the system.
     *
     * @access  public
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    function associateParent($parent_id, $child_id)
    {
        global $HTTP_POST_VARS;
		
        $stmt = "INSERT INTO
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship
                 (
                    cvr_parent_cvo_id,
                    cvr_child_cvo_id					
                 ) VALUES (
                    " .$parent_id. ",
                    " .$child_id. "					
                 )";
        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        } else {
			return 1;
        }
    }
    /**
     * Method used to update details of a controlled vocabulary.
     *
     * @access  public
     * @param   integer $cvo_id The controlled vocabulary ID
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    function update($cvo_id)
    {
        global $HTTP_POST_VARS;

        $stmt = "UPDATE
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 SET 
                    cvo_title = '" . Misc::escapeString($HTTP_POST_VARS["cvo_title"]) . "'
                 WHERE cvo_id = $cvo_id";

        $res = $GLOBALS["db_api"]->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        } else {
			return 1;
        }
    }


    /**
     * Method used to get the title of a specific controlled vocabulary.
     *
     * @access  public
     * @param   integer $cvo_id The controlled vocabulary ID
     * @return  string The title of the controlled vocabulary
     */
    function getTitle($cvo_id)
    {
        $stmt = "SELECT
                    cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 WHERE
                    cvo_id=$cvo_id";
        $res = $GLOBALS["db_api"]->dbh->getOne($stmt);

        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return '';
        } else {
            return $res;
        }
    }


    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system returned in an associative array for drop down lists.
     *
     * @access  public
     * @return  array The list of controlled vocabularies in an associative array (for drop down lists).
     */
    function getAssocList()
    {
        $stmt = "SELECT
                    cvo_id,
					cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
			     WHERE cvo_id not in (SELECT cvr_child_cvo_id from  " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship)
                 ORDER BY
                    cvo_title ASC";
        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            return $res;
        }
    }
	
    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system returned in an associative array for drop down lists.
     *
     * @access  public
     * @return  array The list of controlled vocabularies in an associative array (for drop down lists).
     */
    function getAssocListAll()
    {
        $stmt = "SELECT
                    cvo_id,
					cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 ORDER BY
                    cvo_title ASC";
        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            return $res;
        }
    }	

   /**
     * Method used to get the list of controlled vocabularies available in the 
     * system returned in an associative array for drop down lists.
     *
     * @access  public
     * @return  array The list of controlled vocabularies in an associative array (for drop down lists).
     */
    function getAssocListByID($id)	
    {
	// used by the xsd match forms
        $stmt = "SELECT
                    cvo_id,
					cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
				 WHERE cvo_id = $id";
        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            return $res;
        }
    }	

   /**
     * Method used to get the list of controlled vocabularies available in the 
     * system returned in an associative array for drop down lists.
     *
     * @access  public
     * @return  array The list of controlled vocabularies in an associative array (for drop down lists).
     */
    function getListByID($id)
    {
        $stmt = "SELECT
                    cvo_id,
					cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
				 WHERE cvo_id = $id";
        $res = $GLOBALS["db_api"]->dbh->getAll($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            return $res;
        }
    }	

    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system.
     *
     * @access  public
     * @return  array The list of controlled vocabularies 
     */
    function getList($parent_id=false)
    {
        $stmt = "SELECT
                    *
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab ";

		if (is_numeric($parent_id)) {
			$stmt .=   "," . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship 
					     WHERE cvr_parent_cvo_id = ".$parent_id." AND cvr_child_cvo_id = cvo_id ";			
		} else {
			$stmt .= " WHERE cvo_id not in (SELECT cvr_child_cvo_id from  " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship)";
		}
		$stmt .= "
                 ORDER BY
                    cvo_title ASC";
        $res = $GLOBALS["db_api"]->dbh->getAll($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            if (empty($res)) {
                return array();
            } else {
                return $res;
            }
        }
    }

    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system.
     *
     * @access  public
     * @return  array The list of controlled vocabularies 
     */
    function getAssocListFullDisplay($parent_id=false, $indent="", $level=0, $level_limit=false)
    {
	
		if (is_numeric($level_limit)) {
			if ($level == $level_limit) {
				return array();
			}
		}
		$level++;
        $stmt = "SELECT
                    cvo_id,
					concat('".$indent."',cvo_title) as cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab ";

		if (is_numeric($parent_id)) {
			$stmt .=   "," . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship 
					     WHERE cvr_parent_cvo_id = ".$parent_id." AND cvr_child_cvo_id = cvo_id ";			
		} else {
			$stmt .= " WHERE cvo_id not in (SELECT cvr_child_cvo_id from  " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship)";
		}
		$stmt .= "
                 ORDER BY
                    cvo_title ASC";

        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            if (empty($res)) {
                return array();
            } else {
				$newArray = array();
				$tempArray = array();
				if ($parent_id != false) {
					$indent .= "---------";
				}
				foreach ($res as $key => $data) {
					if ($parent_id != false) {
						$newArray[$key] = $data;
					}
					$tempArray = Controlled_Vocab::getAssocListFullDisplay($key, $indent, $level, $level_limit);					
					if (count($tempArray) > 0) {
						if ($parent_id == false) {
							$newArray['data'][$key] = Misc::array_merge_preserve($newArray[$key], $tempArray);
							$newArray['title'][$key] = $data;
						} else {
							$newArray = Misc::array_merge_preserve($newArray, $tempArray);
						}
					}
				}
				$res = $newArray;
                return $res;
            }
        }
    }



    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system.
     *
     * @access  public
     * @return  array The list of controlled vocabularies 
     */
    function getParentAssocListFullDisplay($child_id, $indent="")
    {
        $stmt = "SELECT
                    cvo_id,
					concat('".$indent."',cvo_title) as cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab ";
			$stmt .=   "," . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship 
					     WHERE cvr_parent_cvo_id = cvo_id AND cvr_child_cvo_id = ".$child_id;			
		$stmt .= "
                 ORDER BY
                    cvo_title ASC";

        $res = $GLOBALS["db_api"]->dbh->getAssoc($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            if (empty($res)) {
                return array();
            } else {
				$newArray = array();
				$tempArray = array();
				foreach ($res as $key => $data) {
					if ($child_id != false) {
						$newArray[$key] = $data;
					}
					$tempArray = Controlled_Vocab::getParentAssocListFullDisplay($key, $indent);					
					if (count($tempArray) > 0) {
						if ($child_id == false) {
							$newArray['data'][$key] = Misc::array_merge_preserve($tempArray, $newArray[$key]);
							$newArray['title'][$key] = $data;
						} else {
							$newArray = Misc::array_merge_preserve($tempArray, $newArray);
						}
					}
				}
				$res = $newArray;
                return $res;
            }
        }
    }

    /**
     * Method used to get the list of controlled vocabularies available in the 
     * system.
     *
     * @access  public
     * @return  array The list of controlled vocabularies 
     */
    function getParentListFullDisplay($child_id, $indent="")
    {
        $stmt = "SELECT
                    cvo_id,
					concat('".$indent."',cvo_title) as cvo_title
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab ";
			$stmt .=   "," . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship 
					     WHERE cvr_parent_cvo_id = cvo_id AND cvr_child_cvo_id = ".$child_id;			
		$stmt .= "
                 ORDER BY
                    cvo_title ASC";

        $res = $GLOBALS["db_api"]->dbh->getAll($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            if (empty($res)) {
                return array();
            } else {
				$newArray = array();
				$tempArray = array();
				foreach ($res as $key => $data) {
					if ($child_id != false) {
						$newArray[$key] = $data;
					}
					$tempArray = Controlled_Vocab::getParentListFullDisplay($key, $indent);					
					if (count($tempArray) > 0) {
						if ($child_id == false) {
							$newArray['data'][$key] = array_merge($tempArray, $newArray[$key]);
							$newArray['title'][$key] = $data;
						} else {
							$newArray = array_merge($tempArray, $newArray);
						}
					}
				}
				$res = $newArray;
                return $res;
            }
        }
    }


	function getAllTreeIDs($parent_id=false) {
	// recursive function to get all the IDs in a CV tree (to be used in counts for entire CV parents including children).
        $stmt = "SELECT
                    cvo_id
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab ";
		if (is_numeric($parent_id)) {
			$stmt .=   "," . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship 
						 WHERE cvr_parent_cvo_id = ".$parent_id." AND cvr_child_cvo_id = cvo_id ";			
		} else {
			$stmt .= " WHERE cvo_id not in (SELECT cvr_child_cvo_id from  " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab_relationship)";
		}
//		echo $stmt."\n<br />";
        $res = $GLOBALS["db_api"]->dbh->getAll($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
			foreach ($res as $row) {
				$tempArray = array();			
				$tempArray = Controlled_Vocab::getAllTreeIDs($row[0]);
//				$newArray[$parent_id] = $parent_id;	
				if (count($tempArray) > 0) {
					$newArray[$row[0]] = $tempArray;
				} else {
					$newArray[$row[0]] = $row[0];
				}

			}

			return $newArray;
		}
	}


    /**
     * Method used to get the details of a specific controlled vocabulary.
     *
     * @access  public
     * @param   integer $cvo_id The controlled vocabulary ID
     * @return  array The controlled vocabulary details
     */
    function getDetails($cvo_id)
    {
        $stmt = "SELECT
                    *
                 FROM
                    " . APP_DEFAULT_DB . "." . APP_TABLE_PREFIX . "controlled_vocab
                 WHERE
                    cvo_id=$cvo_id";
        $res = $GLOBALS["db_api"]->dbh->getRow($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return "";
        } else {
            return $res;
        }
    }

}

// benchmarking the included file (aka setup time)
if (APP_BENCHMARK) {
    $GLOBALS['bench']->setMarker('Included Controlled Vocabulary Class');
}
?>
