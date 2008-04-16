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
// | Authors: Christiaan Kortekaas <c.kortekaas@library.uq.edu.au>,       |
// |          Matthew Smith <m.smith@library.uq.edu.au>                   |
// +----------------------------------------------------------------------+
//
//

include_once(APP_INC_PATH . "class.author.php");
include_once(APP_INC_PATH . "class.lister.php");
include_once(APP_INC_PATH . "class.workflow.php");
include_once(APP_INC_PATH . "class.jhove.php");
include_once(APP_INC_PATH . "class.workflow_trigger.php");
include_once(APP_INC_PATH . "class.statistics.php");
include_once(APP_INC_PATH . "class.citation.php");
include_once(APP_INC_PATH . "class.org_structure.php");
include_once(APP_INC_PATH . "class.record_view.php");
include_once(APP_INC_PATH . "class.user_comments.php");
include_once(APP_PEAR_PATH . "Date.php");

$username = Auth::getUsername();
$isAdministrator = Auth::isAdministrator(); 

if ($isAdministrator) {
	if (APP_FEDORA_SETUP == 'sslall' || APP_FEDORA_SETUP == 'sslapim') {
		$get_url = APP_FEDORA_APIM_PROTOCOL_TYPE.APP_FEDORA_SSL_LOCATION."/get"."/".$pid;
	} else {
		$get_url = APP_FEDORA_APIM_PROTOCOL_TYPE.APP_FEDORA_LOCATION."/get"."/".$pid;	
	}
	$tpl->assign("fedora_get_view", $get_url);	
} else {
	$tpl->assign("fedora_get_view", 0);	
}

$tpl->assign("fez_root_dir", APP_PATH);
$tpl->assign("eserv_url", APP_BASE_URL."eserv/".$pid."/");
$tpl->assign("local_eserv_url", APP_BASE_URL."eserv/".$pid."/");
$tpl->assign("extra_title", "Record #".$pid." Details");

$debug = @$_REQUEST['debug'];
if ($debug == 1) {
	$tpl->assign("debug", "1");
} else {
	$tpl->assign("debug", "0");	
}

if (!empty($pid)) {
	$record = new RecordObject($pid);
}

if (!empty($pid) && $record->checkExists()) {
    
	$tpl->assign("pid", $pid);
	$deleted = false;
	if (@$show_tombstone) {
		$tpl->assign('show_tombstone',true);
		// check if this record has been deleted
		if ($record->isDeleted()) {
			$tpl->assign('deleted',true);
			$deleted = true;
			$history_res = History::searchOnPid($pid, 
								array('pre_detail' => '%Marked Duplicate of %'));
	    	if (!empty($history_res)) {
				preg_match('/Marked Duplicate of (\S+)/', $history_res[0]['pre_detail'], $matches);
	    		$tpl->assign('duplicate_pid',$matches[1]);
	    		$tpl->assign('duplicate_premis',$history_res[0]);
	    		
    		}
		}
	}
	
	$xdis_id = $record->getXmlDisplayId();
	$tpl->assign("xdis_id", $xdis_id);
	$xdis_title = XSD_Display::getTitle($xdis_id);	
    $tpl->assign("xdis_title", $xdis_title);
	if (!is_numeric($xdis_id)) {
		$xdis_id = @$_POST["xdis_id"] ? $_POST["xdis_id"] : @$_GET["xdis_id"];	
		if (is_numeric($xdis_id)) { // must have come from select xdis so save xdis in the Fez MD
			$record->updateAdminDatastream($xdis_id);
		}
	}
	if (!is_numeric($xdis_id)) { // if still can't find the xdisplay id then ask for it
		Auth::redirect(APP_RELATIVE_URL . "select_xdis.php?return=view_form&pid=".$pid.$extra_redirect, false);
	}
	
	$canEdit = false;
	$canView = true;
	
	$canEdit = $record->canEdit(false);
    if ($canEdit == true) {
		$canView = true;
	} else {
		$canView = $record->canView();
	}
	
	$tpl->assign("isViewer", $canView);
	if ($canView) {

        $ret_id = 3;
        $strict = false;
        $workflows = array_merge(   $record->getWorkflowsByTriggerAndRET_ID('Update', $ret_id, $strict),
                                    $record->getWorkflowsByTriggerAndRET_ID('Export', $ret_id, $strict));
        
        // check which workflows can be triggered
        $workflows1 = array();
        if (is_array($workflows)) {
            foreach ($workflows as $trigger) {
                if (WorkflowTrigger::showInList($trigger['wft_options']) 
                        && Workflow::canTrigger($trigger['wft_wfl_id'], $pid)) {
                    $workflows1[] = $trigger;
                }
            }
            $workflows = $workflows1;
        }
        
        $tpl->assign("workflows", $workflows); 
		$tpl->assign("isEditor", $canEdit);
		$tpl->assign("sta_id", $record->getPublishedStatus()); 
		
		$display = new XSD_DisplayObject($xdis_id);
		$xsd_display_fields = $record->display->getMatchFieldsList(array("FezACML"), array(""));  // XSD_DisplayObject

		$tpl->assign("xsd_display_fields", $xsd_display_fields);
		$details = $record->getDetails();
        	
		$parents = Record::getParentsDetails($pid);

        // do citation before mucking about with the details array
        $citation_html = Citation::renderCitation($xdis_id, $details, $xsd_display_fields);
        $tpl->assign('citation', $citation_html);

		$parent_relationships = array(); 
		foreach ($parents as $parent) {
			$parent_rel = XSD_Relationship::getColListByXDIS($parent['rek_display_type']);
			$parent_relationships[$parent['rek_pid']] = array();
			foreach ($parent_rel as $prel) {
				array_push($parent_relationships[$parent['rek_pid']], $prel);
			}
			array_push($parent_relationships[$parent['rek_pid']], $parent['rek_display_type']);
		} 
		// Now generate the META Tag headers
		$meta_head = '<meta name="DC.Identifier" schema="URI" content="'.substr(APP_BASE_URL,0,-1).$_SERVER['PHP_SELF'].'?'.$_SERVER['QUERY_STRING'].'"/>'."\n";
		// Get some extra bits out of the record
		foreach ($xsd_display_fields as $dis_key => $dis_field) {
		    
			// Look for the meta tag header items
			if (($dis_field['xsdmf_enabled'] == 1) && ($dis_field['xsdmf_meta_header'] == 1) && (trim($dis_field['xsdmf_meta_header_name']) != "")) {
				if (is_array($details[$dis_field['xsdmf_id']])) {
					foreach ($details[$dis_field['xsdmf_id']] as $ckey => $cdata) {
						if ($cdata != "") {
							$meta_head .= '<meta name="'.$dis_field['xsdmf_meta_header_name'].'" content="'.htmlspecialchars(trim($cdata), ENT_QUOTES).'"/>'."\n";
						}
					}
				} else {
					if ($details[$dis_field['xsdmf_id']] != "") {
						$meta_head .= '<meta name="'.$dis_field['xsdmf_meta_header_name'].'" content="'.htmlspecialchars(trim($details[$dis_field['xsdmf_id']]), ENT_QUOTES).'"/>'."\n";
						if ($dis_field['xsdmf_meta_header_name'] == "DC.Title") {
							$tpl->assign("extra_title", trim($details[$dis_field['xsdmf_id']]));
						}
					}
				}
			}
			if ($dis_field['xsdmf_enabled'] == 1) {
				// get the created / updated and depositor info
				if ($dis_field['xsdmf_element'] == "!created_date") {
					if (!empty($details[$dis_field['xsdmf_id']])) {
						if (is_array($details[$dis_field['xsdmf_id']])) {
							foreach ($details[$dis_field['xsdmf_id']] as $ckey => $cdata) {		
								$created_date = Date_API::getFormattedDate($cdata);
							}
						} else {
							$created_date = Date_API::getFormattedDate($details[$dis_field['xsdmf_id']]);
						}
					}
				}
				if ($dis_field['xsdmf_element'] == "!depositor") {
					if (!empty($details[$dis_field['xsdmf_id']])) {
						if (is_array($details[$dis_field['xsdmf_id']])) {
							foreach ($details[$dis_field['xsdmf_id']] as $ckey => $cdata) {		
								$depositor_id = $cdata;								
								$depositor = User::getFullName($cdata);
							}
						} else {
							$depositor_id = $details[$dis_field['xsdmf_id']];
							$depositor = User::getFullName($details[$dis_field['xsdmf_id']]);
						}
					}
				}				
				if ($dis_field['xsdmf_element'] == "!depositor_affiliation") {
					if (!empty($details[$dis_field['xsdmf_id']])) {
						if (is_array($details[$dis_field['xsdmf_id']])) {
							foreach ($details[$dis_field['xsdmf_id']] as $ckey => $cdata) {		
								$depositor_org_id = $cdata;								
								$depositor_org = Org_Structure::getTitle($cdata);
							}
						} else {
							$depositor_org_id = $details[$dis_field['xsdmf_id']];
							$depositor_org =  Org_Structure::getTitle($details[$dis_field['xsdmf_id']]);
						}
					}
				}								
			}
		}
		
        $tpl->assign('meta_head', $meta_head);		
		$record_view = new RecordView($record);	// record viewer object
		$details = $record_view->getDetails();
		
	} else {
		$tpl->assign("show_not_allowed_msg", true);
	}
	
	if (empty($details)) {
		$tpl->assign('details', '');
	} else {
		$linkCount = 0;
		$fileCount = 0;
		
		$datastreams = Fedora_API::callGetDatastreams($pid);
		$datastreamsAll = $datastreams;		
		$datastreams = Misc::cleanDatastreamListLite($datastreams, $pid);
		
		foreach ($datastreams as $ds_key => $ds) {
			
		    if ($datastreams[$ds_key]['controlGroup'] == 'R') {
				$linkCount++;				
			}
			
			if ($datastreams[$ds_key]['controlGroup'] == 'R' && $datastreams[$ds_key]['ID'] != 'DOI') {
				$datastreams[$ds_key]['location'] = trim($datastreams[$ds_key]['location']);
				
				// Check for APP_LINK_PREFIX and add if not already there
				if (APP_LINK_PREFIX != "") {
					if (!is_numeric(strpos($datastreams[$ds_key]['location'], APP_LINK_PREFIX))) {
						$datastreams[$ds_key]['location'] = APP_LINK_PREFIX.$datastreams[$ds_key]['location'];
					}
				}
			} elseif ($datastreams[$ds_key]['controlGroup'] == 'M') {
				
			    $fileCount++;
                if (is_numeric(strrpos($datastreams[$ds_key]['ID'], "."))) {
				    $Jhove_DS_ID = "presmd_".substr($datastreams[$ds_key]['ID'], 0, strrpos($datastreams[$ds_key]['ID'], ".")).".xml";
                } else {
                    $Jhove_DS_ID = "presmd_".$datastreams[$ds_key]['ID'].".xml";
                }
                
				foreach ($datastreamsAll as $dsa) {
				    
					if ($dsa['ID'] == $Jhove_DS_ID) {
						$Jhove_XML = Fedora_API::callGetDatastreamDissemination($pid, $Jhove_DS_ID);
						
						if(!empty($Jhove_XML['stream'])) {
    						$jhoveHelp = new Jhove_Helper($Jhove_XML['stream']);
    						
    						$fileSize = $jhoveHelp->extractFileSize();
    						$fileSize = Misc::size_hum_read($fileSize);
    						$datastreams[$ds_key]['archival_size'] = $fileSize;
    						
    						$spatialMetrics = $jhoveHelp->extractSpatialMetrics();
    						
    						if( is_numeric($spatialMetrics[0]) && $spatialMetrics[0] > 0 ) {
                                $tpl->assign("img_width", $spatialMetrics[0]);
    						}
    						  
    						if( is_numeric($spatialMetrics[1]) && $spatialMetrics[1] > 0 ) {
                                $tpl->assign("img_heigth", $spatialMetrics[1]);
    						}
    						
    						unset($jhoveHelp);
    						unset($Jhove_XML);
						}
					}
				}			
				$datastreams[$ds_key]['FezACML'] = Auth::getAuthorisationGroups($pid, $datastreams[$ds_key]['ID']);
				$datastreams[$ds_key]['downloads'] = Statistics::getStatsByDatastream($pid, $ds['ID']);			
				Auth::getAuthorisation($datastreams[$ds_key]);
				
			}
			
            if ($datastreams[$ds_key]['controlGroup'] == 'R' && $datastreams[$ds_key]['ID'] == 'DOI') {
                $datastreams[$ds_key]['location'] = trim($datastreams[$ds_key]['location']);
                $tpl->assign('doi', $datastreams[$ds_key]);
            }
		} 
		$tpl->assign("datastreams", $datastreams);
		$tpl->assign("ds_get_path", APP_FEDORA_GET_URL."/".$pid."/");
		$tpl->assign("parents", $parents);
		
		if (count($parents) > 1) {
			$tpl->assign("parent_heading", "Collections:");
		} else {
			$tpl->assign("parent_heading", "Collection:");				
		}
		
		//what does this record succeed?
		$hasVersions = 0;
		$derivations = Record::getParentsAll($pid, 'isDerivationOf', true);
		//print_r($derivations); exit;
		if (count($derivations) == 0) {
			$derivations[0]['rek_title'][0] = Record::getSearchKeyIndexValue($pid, "Title");
			$derivations[0]['rek_pid'] = $pid;			
		} else {
			$hasVersions = 1;
		}
//		print_r($derivations);
		//are there any other records that also succeed this parent
		foreach ($derivations as $devkey => $dev) { // gone all the way up, now go back down getting ALL the children as we ride the spiral
			$child_devs = Record::getChildrenAll($derivations[$devkey]['pid'], "isDerivationOf", false);
			if (count($child_devs) != 0) {
				$hasVersions = 1;
			}
			$derivations[$devkey]['children'] = $child_devs;
		}
//		print_r($derivations);
		$derivationTree = "";
		if ($hasVersions == 1) {
			Record::generateDerivationTree($pid, $derivations, $derivationTree);
		}
				
		$tpl->assign("linkCount", $linkCount);
		$tpl->assign("hasVersions", $hasVersions);
		$tpl->assign("fileCount", $fileCount);
		$tpl->assign("derivationTree", $derivationTree);
		$tpl->assign("created_date", $created_date);
		$tpl->assign("depositor", $depositor);
		$tpl->assign("depositor_id", $depositor_id);
		$tpl->assign("depositor_org", $depositor_org);
		$tpl->assign("depositor_org_id", $depositor_org_id);
		$tpl->assign("details", $details);
        $tpl->assign('title', $record->getTitle());		

		$tpl->assign("statsAbstract", Statistics::getStatsByAbstractView($pid));				
		$tpl->assign("statsFiles", Statistics::getStatsByAllFileDownloads($pid));						
        // get prev / next info
        
        // Check if we have moved onto the next listing page
//        if (@$_GET['next']) {
//            $res = getNextPage();
//        }
//        if (@$_GET['prev']) {
//            $res = getPrevPage();
//        }
//        if (@$_GET['next'] || @$_GET['prev']) {
//            $_SESSION['list'] = $res['list'];
//            $_SESSION['list_params'] = $res['list_params'];
//            $_SESSION['list_info'] = $res['list_info'];
//            $_SESSION['view_page'] = $res['list_info']['current_page'];
//        }

        // Get the current listing 
        $list = $_SESSION['list'];
        $list_info = $_SESSION['list_info'];
        $view_page = $_SESSION['view_page'];

        // find current position in list
        $list_idx = null;
		if (is_array($list)) {
			foreach ($list as $key => $item) {
				if ($item['rek_pid'] == $pid) {
					$list_idx = $key;
					break;
				}
			}
		}
        $prev = null;  // the next item in the list
        $next = null;  // the previous item in the list
        $go_next = null;  // whether we need to page down
        $go_prev = null;  // whether we need to page up
        if (!is_null($list_idx)) {
            if ($list_idx > 0) {
                $prev = $list[$list_idx-1];
            } else {
                $res = getPrevPage();
                if (!empty($res)) {
                    $prev = $res['list'][count($res['list'])-1];
                    $go_prev = true;
                }
            }
            if ($list_idx < count($list)-1) {
                $next = $list[$list_idx+1];
            } else {
                $res = getNextPage();
                if (!empty($res)) {
                    $next = $res['list'][0];
                    $go_next = true;
                }
            }
        }
        $tpl->assign(compact('prev','next','go_next','go_prev'));
	}
} else {
    $tpl->assign('not_exists', true);
	$tpl->assign("show_not_allowed_msg", true);
}

// display user comments, if any
$uc = new UserComments($pid);

// Users must be logged in to submit comments
if(!empty($username))
{
    $tpl->assign('addusercomment', true);
}
$tpl->assign('displayusercomments', true);
$tpl->assign('usercomments', $uc->comments);


function getNextPage()
{
    $params = $_SESSION['list_params'];
    $info = $_SESSION['list_info'];
    $view_page = $_SESSION['view_page'];
    if ($view_page < $info['last_page']) {
        $params['pagerRow'] = $view_page + 1;
        $res = Lister::getList($params, false);
        $res['list_params'] = $params;
        return $res;
    }
    return array();
}
function getPrevPage()
{
    $params = $_SESSION['list_params'];
    $info = $_SESSION['list_info'];
    $view_page = $_SESSION['view_page'];
    if ($view_page > 0) {
        $params['pagerRow'] = $view_page - 1;
        $res = Lister::getList($params, false);
        $res['list_params'] = $params;
        return $res;
    }
    return array();
}
//echo ($GLOBALS['bench']->getOutput());
?>
