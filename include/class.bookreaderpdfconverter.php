<?php

include_once(dirname(dirname(__FILE__)).DIRECTORY_SEPARATOR."config.inc.php");

class bookReaderPDFConverter
{
    private $bookreaderDataPath;
    private $sourceFilePath;
    private $sourceFileStat = array();
    private $log;
    private $queue = array();

    public function __construct()
    {
        $this->log = FezLog::get();
    }

    /**
     * Set input resource (PDF) parameters.
     * @param  $pid
     * @param  $sourceFile
     * @return void
     */
    public function setSource($pid, $sourceFile)
    {
        $sourceFile = trim($sourceFile);

        if(strstr($pid,':'))
        {
            $pid = str_replace(':','_',$pid);
        }

        //Is the source file on the filesystem or do we need to download it?
        if(strstr($sourceFile, 'http://') || strstr($sourceFile, 'https://'))
        {
            $this->sourceFilePath = $this->getURLSource($sourceFile);
        }
        else
        {
            $this->sourceFilePath = $sourceFile;
        }
        $this->sourceInfo();
        $this->bookreaderDataPath = APP_PATH . BR_IMG_DIR . $pid . '/' . $this->sourceFileStat['filename'];
    }

    /**
     * Set queue of pdfs to process. The queue array elements are arrays
     * in the form array($pid,$sourcePath,$conversionMethod).
     * @param array $queue
     * @return void
     */
    public function setQueue(array $queue)
    {
        $this->queue = $queue;
    }

    /**
     * Create a queue based on PID. Includes all pdf resources for that PID.
     * @param  $pid
     * @param string $convMeth
     * @return void
     */
    public function setPIDQueue($pid, $convMeth='pdfToJpg')
    {
        $datastreams = Fedora_API::callGetDatastreams($pid);
        $srcURL = APP_FEDORA_GET_URL."/".$pid . '/';
        $q = array();

        foreach($datastreams as $ds)
        {
            if($ds['MIMEType'] == 'application/pdf')
            {
                $q[] = array($pid, $srcURL .$ds['ID'], $convMeth);
            }
        }
        $this->queue = $q;
    }

    /**
     * Check if resource images have been generated by
     * performing a page count.
     * @param  $resourcePath
     * @return bool
     */
    public function resourceGenerated($resourcePath)
    {
        $pageCount = count(array_filter(scandir($resourcePath),
                         array($this, 'ct')));

        return ($pageCount > 0) ? true : false;
    }

    public function ct($element)
    {
        return !in_array($element, array('.','..'));
    }

    /**
     * Gather and store information about the source PDF.
     * @return void
     */
    protected function sourceInfo()
    {
        $parts = pathinfo($this->sourceFilePath);
        $this->sourceFileStat = $parts;
    }

    /**
     * Download a pdf from a URL in chunks and save to a tmp location.
     * @param  $url
     * @return string
     */
    protected function getURLSource($url)
    {
        $parts = pathinfo($url);
        $fhurl = fopen($url, 'rb');
        $tmpPth = APP_TEMP_DIR . $parts['basename'];
        $fhfs = fopen($tmpPth, 'ab');

        while(!feof($fhurl))
        {
            fwrite($fhfs, fread($fhurl, 1024));
        }

        fclose($fhurl);
        fclose($fhfs);

        return $tmpPth;
    }

    /**
     * Create a directory for this PDF's images if required
     * @return bool|int
     */
    protected function makePath()
    {
        $dir = 0;
        if(!is_dir($this->bookreaderDataPath))
        {
            $dir = mkdir($this->bookreaderDataPath, 0755, true);
        }
        return $dir;
    }

    /**
     * Run the selected conversion method.
     * @param  $conversionType
     * @param bool $forceRegenerate
     * @return void
     */
    public function run($conversionType, $forceRegenerate=false)
    {
        if(method_exists($this, $conversionType))
        {
            //Generate the resource images if they're not already there or if we are forcing it to do so.
            $resourceGenerated = ($forceRegenerate) ? false :
                    $this->resourceGenerated($this->bookreaderDataPath);
            if(!$resourceGenerated)
            {
                $this->$conversionType();
            }

            //Delete the tmp source file if there is one.
            if(strstr($this->sourceFilePath, APP_TEMP_DIR))
            {
                unlink($this->sourceFilePath);
            }
        }
        else
        {
            $this->log->err('Conversion method does not exist:' . __FILE__ . ':' . __LINE__);
        }
    }

    /**
     * Run the bookreader job queue.
     * @param bool $forceRegenerate
     * @return void
     */
    public function runQueue($forceRegenerate=false)
    {
        foreach($this->queue as $job)
        {
            if(is_array($job) && count($job) == 3)
            {
                $this->setSource($job[0],$job[1]);
                $this->run($job[2], $forceRegenerate);
            }
            else
            {
                $this->log->err('Malformed job in bookreader queue:' . __FILE__ . ':' . __LINE__);
            }
        }
    }

    /**
     * Perform a conversion of the PDF to png format. One image per page.
     * @return void
     *
     */
    protected function pdfToPng()
    {
        $this->makePath();
        if(is_writable($this->bookreaderDataPath))
        {
            $cmd = GHOSTSCRIPT_PTH . ' -q -dBATCH -dNOPAUSE -sDEVICE=png16m -r150 -sOutputFile=' .
                   $this->bookreaderDataPath . '/' . $this->sourceFileStat['filename'] . '-%04d.png ' .
                   realpath($this->sourceFilePath);
            shell_exec(escapeshellcmd($cmd));
        }
        else
        {
            $this->log->err('Unable to write page images to directory:' . __FILE__ . ':' . __LINE__);
        }
    }

    /**
     * Perform a conversion of the PDF to jpg format. One image per page.
     * @return void
     *
     */
    protected function pdfToJpg()
    {
        $this->makePath();
        if(is_writable($this->bookreaderDataPath))
        {
            $cmd = GHOSTSCRIPT_PTH . ' -q -dBATCH -dNOPAUSE -dJPEGQ=80 -sDEVICE=jpeg -r150 -sOutputFile=' .
                   $this->bookreaderDataPath . '/' . $this->sourceFileStat['filename'] . '-%04d.jpg ' .
                   realpath($this->sourceFilePath);
            shell_exec(escapeshellcmd($cmd));
        }
        else
        {
            $this->log->err('Unable to write page images to directory:' . __FILE__ . ':' . __LINE__);
        }
    }
}