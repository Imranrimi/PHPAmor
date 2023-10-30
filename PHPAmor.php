<?php
class PHPAmor
{
    private $logFile; // Path to the log file for recording security issues
    private $dsn;
    private $username;
    private $password;
 

    public function setLogFilePath($logFilePath)
    {
        $this->logFile = $logFilePath;
        return $this;
    }

    public function checkRequest($request): bool
    {
        // Check for XXS and SQL Injection
        if ($this->isXSS($request)) {
            $this->logReport("XSS Security threat detected: ".$this->array_to_htmlentities($request));
            return FALSE;
        } else {
            return TRUE; // Request is safe, continue to the application
        }
    }
    private function array_to_htmlentities(array $array): string
    {
         $result = array_map('htmlspecialchars', $array);

         return json_encode($result);
    }

    private function isXSS($data)
    {
        // Check for potential XSS by looking for script tags and known XSS patterns
        $patterns = array(
            '/<script>[\s\S]*<\/script>/i',
            // Malicious JavaScript code
            '/<.*script.*>[\s\S]*<\/.*script.*>/i',
            // HTML markup containing scripts
            '/<.*>[\s\S]*<.*>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<.*>[\s\S]*<\/.*>/i',
            // XML data with embedded scripts
            '/"[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*"/i',
            // JSON data with scripts
            '/<svg>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<\/svg>/i',
            // SVG images with embedded scripts
            '/data:text\/html;[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>/i',
            // Data URIs that include script content
            '/<style>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<\/style>/i',
            // CSS styles with scripts
            // U
        );
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        return true; // Found XXS attack
                    }
                }
            }
        }

        return false; // No XSS detected
    }

    private function logReport($message)
    {
        // Implement logging to a log file with $message
        file_put_contents($this->logFile, "[" . date("Y-m-d H:i:s") . "] " . $message . "\n", FILE_APPEND);
    }

   



    /*
     ==================================================
     |||||||| Amor secured Database interaction ||||||||
     ===================================================
     */
    public function setDBInformation($driver, $host, $database, $username, $password){
        switch ($driver) {
            case 'mysql':
                $this->dsn = 'mysql:host=' . $host . ';dbname=' . $database . ';charset=utf8';
                break;
            case 'pgsql':
                $this->dsn = 'pgsql:host=' . $host . ';dbname=' . $database . ';port=5432';
                break;
            case 'sqlite':
                $this->dsn = 'sqlite:' . $database . '.sqlite';
                break;
            case 'sqlsrv':
                $this->dsn = 'sqlsrv:server=' . $host . ';database=' . $database;
                break;
            case 'oci':
                $this->dsn = 'oci:dbname=' . $database . ';charset=utf8';
                break;
            default:
                throw new Exception('Invalid database driver');
        }
        $this->username = $username;
        $this->password = $password;
        return $this;
    }
    private function connect()
    {
       
        try {
            $pdo = new PDO($this->dsn, $this->username, $this->password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            throw new Exception('Failed to connect to database: ' . $e->getMessage());
        }

        return $pdo;

    }

    private function disconnect($con)
    {
        $con = null;
    }

    private function bindValues(\PDOStatement $stmt, array $data)
    {
            try {
                foreach ($data as $key => $value)
                {
                    $stmt->bindValue($key, $value);

                }

            } catch (\PDOException $th) {
                $this->logReport("Possible of SQL Injection: ". $th->getMessage());
                throw new Exception('Error: '. $th->getMessage());
            }
        return $stmt;
    }
    public function execute($sql, array $data, $fetchMode = NULL, $fetch = NULL)
    {
        
        try{
            $con = $this->connect();
            $stmt = $con->prepare($sql);
            $stmt = $this->bindValues($stmt, $data);
            var_dump($stmt->execute());exit;
            $stmt->execute();
            $this->disconnect($con);
            if ($fetchMode !== NULL ) {
                if($fetch !== NULL){
                    return $stmt->$fetch($fetchMode);
                }
            }
            return TRUE;
        } catch (\PDOException $e) {
            $this->disconnect($con);
            $this->logReport("Possible of SQL Injection: ".$e->getMessage());
            return FALSE;

        } catch (\Throwable $e) {
            $this->disconnect($con);
            $this->logReport("Possible of SQL Injection: ".$e->getMessage());
            return FALSE;
        }

    }
    public function query($sql, $fetchMode = NULL, $fetch = NULL)
    {
        try{
            $con = $this->connect();
            $stmt = $con->query($sql);
            $this->disconnect($con);
            if ($fetchMode !== NULL ) {
                if($fetch !== NULL){
                    return $stmt->$fetch($fetchMode);
                }
            }
            return TRUE;

        } catch (\PDOException $e) {
            $this->disconnect($con);
            $this->logReport("Possible of SQL Injection: ".$e->getMessage());
            return FALSE;
        } catch (\Throwable $e) {
            $this->disconnect($con);
            $this->logReport("Possible of SQL Injection: ".$e->getMessage());
            return FALSE;
        }

    }
}
