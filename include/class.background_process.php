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
// |          Lachlun Kuhn <l.kuhn@library.uq.edu.au>,                    |
// |          Rhys Palmer <r.rpalmer@library.uq.edu.au>                   |
// +----------------------------------------------------------------------+

define('BGP_UNDEFINED', 0);
define('BGP_RUNNING',   1);
define('BGP_FINISHED',  2);

include_once(APP_INC_PATH . "class.date.php");
/**
  * This is a virtual class.
  * Subclass this to make a background process with a customised 'run' method.
  */
class BackgroundProcess {
    var $bgp_id;
    var $details;
    var $inputs;
    var $include; // set this to the include file where the subclass is declared
    var $name; // set this to the name of the process where the subclass is declared
    var $states = array(
            0 => 'Undefined',
            1 => 'Running',
            2 => 'Done'
            );
    var $local_session = array();
    var $progress = 0;
    var $wfses_id = null; // id of workflow session to resume when this background process finishes


    /***** Mixed *****/

    function __construct($bgp_id=null)
    {
        $this->bgp_id = $bgp_id;
    }

    function getDetails()
    {
        if (!$this->details || $this->details['bgp_id'] != $this->bgp_id) {
            $dbtp =  APP_TABLE_PREFIX;
            $stmt = "SELECT * FROM ".$dbtp."background_process WHERE bgp_id='".$this->bgp_id."'";
            $res = $GLOBALS['db_api']->dbh->getAll($stmt,DB_FETCHMODE_ASSOC);
            if (PEAR::isError($res)) {
                Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
                return array();
            } else {
			}
            	
            

            $this->details = $res[0];
        }
        return $this->details;
    }

    function serialize()
    {
        $serialized = Misc::escapeString(serialize($this));
        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "UPDATE ".$dbtp."background_process SET bgp_serialized='".$serialized."' WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
    }

    function setProgress($percent)
    {
        $percent = Misc::escapeString($percent);
        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "UPDATE ".$dbtp."background_process SET bgp_progress='".$percent."' WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
        $this->setHeartbeat();
    }

    function incrementProgress()
    {
    	$this->setProgress(++$this->progress);
    }

    function setStatus($msg)
    {
        echo $msg."\n";
        $msg = Misc::escapeString($msg);
        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "UPDATE ".$dbtp."background_process SET bgp_status_message='".$msg."' WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
        $this->setHeartbeat();
    }

    function setState($state)
    {
        $state = Misc::escapeString($state);
        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "UPDATE ".$dbtp."background_process SET bgp_state='".$state."' WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
        $this->setHeartbeat();
    }

    function setHeartbeat()
    {
        $dbtp =  APP_TABLE_PREFIX;
//		$utc_date = Date_API::getDateGMT(date("Y-m-d H:i:s"));
		$utc_date = Date_API::getSimpleDateUTC();		
        $stmt = "UPDATE ".$dbtp."background_process SET bgp_heartbeat='".$utc_date."' WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
    }

    function setExportFilename($filename, $headers)
    {
        $dbtp =  APP_TABLE_PREFIX;
        $filename = Misc::escapeString($filename);
        $headers = Misc::escapeString($headers);
        $stmt = "UPDATE ".$dbtp."background_process SET 
            bgp_filename='".$filename."',
            bgp_headers='".$headers."'
            WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
    }

    function getExportFile()
    {
        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "SELECT bgp_filename, bgp_headers, bgp_usr_id 
            FROM ".$dbtp."background_process WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->getRow($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
        if (Auth::getUserID() == $res['bgp_usr_id']) {
            $headers = explode("\n", $res['bgp_headers']);
            foreach ($headers as $head) {
                header($head);
            }
            readfile($res['bgp_filename']);
        } else {
            echo "Not authorised: Username doesn't match";
        }
        exit;
    }
 
    /***** APACHE SIDE *****/
    
    /**
     * Start a background process
     * @param string $inputs A serialized array or object that is the inputs to the process to be run.  
     *                       e.g. serialize(compact('pid','dsID'))
     * @param int $usr_id The user who will own the process.
     */
    function register($inputs, $usr_id, $wfses_id = null) 
    {
        $this->inputs = $inputs;
        $this->wfses_id = $wfses_id; // optional workflow session
        $usr_id = Misc::escapeString($usr_id);
        $dbtp =  APP_TABLE_PREFIX;
        // keep background log files in a subdir so that they don't clutter up the /tmp dir so much
        if (!is_dir(APP_TEMP_DIR."fezbgp")) {
            mkdir(APP_TEMP_DIR."fezbgp");
        }

		$utc_date = Date_API::getSimpleDateUTC();
        $stmt = "INSERT INTO ".$dbtp."background_process (bgp_usr_id,bgp_started,bgp_name,bgp_include) 
            VALUES ('".$usr_id."', '".$utc_date."', '".$this->name."','".$this->include."')";
        $res = $GLOBALS['db_api']->dbh->query($stmt);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
            return -1;
        }
        $this->bgp_id = $GLOBALS['db_api']->get_last_insert_id();
        $this->serialize();
        $command = APP_PHP_EXEC." \"".APP_PATH."misc/run_background_process.php\" ".$this->bgp_id." \""
            .APP_PATH."\" > ".APP_TEMP_DIR."fezbgp/fezbgp_".$this->bgp_id.".log";
        if ((stristr(PHP_OS, 'win')) && (!stristr(PHP_OS, 'darwin'))) { // Windows Server
            pclose(popen("start /min /b ".$command,'r'));
        } else {
            exec($command." 2>&1 &");
        }
        return $this->bgp_id;
    } 

    
    /***** CLI SIDE *****/

    /**
     * subclass this function for your background process
     */
    function run()
    {
    }

    /**
      * Authenticate the background process 
      */
    function setAuth()
    {
        global $auth_isBGP, $auth_bgp_obj;
        $auth_isBGP = true;
        $GLOBALS['auth_bgp_obj'] = &$this;

        $session =& $this->local_session;

        $dbtp =  APP_TABLE_PREFIX;
        $stmt = "SELECT * FROM ".$dbtp."background_process WHERE bgp_id='".$this->bgp_id."'";
        $res = $GLOBALS['db_api']->dbh->getRow($stmt, DB_FETCHMODE_ASSOC);
        if (PEAR::isError($res)) {
            Error_Handler::logError(array($res->getMessage(), $res->getDebugInfo()), __FILE__, __LINE__);
        }
        $usr_id = $res['bgp_usr_id'];
        $usr_obj = new User;
        $user_det = $usr_obj->getDetailsByID($usr_id);
        $username = $user_det['usr_username'];

		if( strcmp($username,"") == 0 )
		{
			Error_Handler::logError(array("WARNING: username is blank.  Cannot authenticate for running background process test.  Most likely the user (id: '".$usr_id."') doesn't exist or has been deleted."), __FILE__, __LINE__);
		}
        // the password is not used.  The auth system won't be able to access any AD info
        Auth::LoginAuthenticatedUser($username, 'blah'); 	
    }

    function getSession()
    {
        return $this->local_session;
    }
   
}

