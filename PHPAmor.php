<?php

class PHPAmor
{
    private const TOKEN_SESSION_KEY = "csrf_token";
    private static $logFile;

    private $dsn;
    private $username;
    private $password;

    /**
     * Set the path for the log file to record security issues.
     */
    public function setLogFilePath($logFilePath)
    {
        self::$logFile = $logFilePath;
    }

    /**
     * Check for XSS and SQL Injection in the request.
     */
    public function checkRequest($request): bool
    {
        if ($this->isXSS($request)) {
            self::logReport("XSS Security threat detected: " . $this->arrayToHtmlEntities($request));
            return false;
        } else {
            return true; // Request is safe, continue to the application
        }
    }

    /**
     * Convert an array to HTML entities.
     */
    private function arrayToHtmlEntities(array $array): string
    {
        $result = array_map('htmlspecialchars', $array);
        return json_encode($result);
    }

    /**
     * Check for potential XSS by looking for script tags and known XSS patterns.
     */
    private function isXSS($data)
    {
        $patterns = array(
            '/<script>[\s\S]*<\/script>/i',
            '/<.*script.*>[\s\S]*<\/.*script.*>/i',
            '/<.*>[\s\S]*<.*>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<.*>[\s\S]*<\/.*>/i',
            '/"[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*"/i',
            '/<svg>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<\/svg>/i',
            '/data:text\/html;[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>/i',
            '/<style>[\s\S]*<.*script.*>[\s\S]*<\/.*script.*>[\s\S]*<\/style>/i',
        );

        foreach ($data as $key => $value) {
            if (is_string($value)) {
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        return true; // Found XSS attack
                    }
                }
            }
        }

        return false; // No XSS detected
    }

    /**
     * Log security reports to the specified log file.
     */
    private static function logReport($message)
    {
        file_put_contents(self::$logFile, "[" . date("Y-m-d H:i:s") . "] " . $message . "\n", FILE_APPEND);
    }

    /**
     * Set database information based on the driver.
     */
    public function setDBInformation($driver, $host, $database, $username, $password)
    {
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

    /**
     * Establish a database connection.
     */
    private function connect()
    {
        try {
            $pdo = new PDO($this->dsn, $this->username, $this->password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            self::logReport("Failed to connect to database: " . $e->getMessage());
            throw new Exception('Failed to connect to database: ' . $e->getMessage());
        }

        return $pdo;
    }

    /**
     * Disconnect from the database.
     */
    private function disconnect($con)
    {
        $con = null;
    }

    /**
     * Bind values to a prepared statement.
     */
    private function bindValues(\PDOStatement $stmt, array $data)
    {
        try {
            foreach ($data as $key => $value) {
                $stmt->bindValue($key, $value);
            }
        } catch (\PDOException $th) {
            self::logReport("Possible SQL Injection: " . $th->getMessage());
            throw new Exception('Error: ' . $th->getMessage());
        }

        return $stmt;
    }

    /**
     * Execute a prepared SQL statement.
     */
    public function execute($sql, array $data, $fetchMode = null, $fetch = null)
    {
        try {
            $con = $this->connect();
            $stmt = $con->prepare($sql);
            $stmt = $this->bindValues($stmt, $data);
            $stmt->execute();
            $this->disconnect($con);

            if ($fetchMode !== null) {
                if ($fetch !== null) {
                    return $stmt->$fetch($fetchMode);
                }
            }

            return true;
        } catch (\PDOException $e) {
            $this->disconnect($con);
            self::logReport("Something Bad Happens: " . $e->getMessage());
            return false;
        } catch (\Throwable $e) {
            $this->disconnect($con);
            self::logReport("Something Bad Happens: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Execute a query and return the result.
     */
    public function query($sql, $fetchMode = null, $fetch = null)
    {
        try {
            $con = $this->connect();
            $stmt = $con->query($sql);
            $this->disconnect($con);

            if ($fetchMode !== null) {
                if ($fetch !== null) {
                    return $stmt->$fetch($fetchMode);
                }
            }

            return true;
        } catch (\PDOException $e) {
            $this->disconnect($con);
            self::logReport("Something Bad Happens: " . $e->getMessage());
            return false;
        } catch (\Throwable $e) {
            $this->disconnect($con);
            self::logReport("Something Bad Happens: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Generate a CSRF token.
     */
    private static function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Validate CSRF token from form data.
     */
    public static function validateCSRF(array $formData): bool
    {
        $token = $formData[self::TOKEN_SESSION_KEY];

        if (!isset($_SESSION[self::TOKEN_SESSION_KEY])) {
            self::logReport("No csrf_token detected from the server: " . json_encode(array_map('htmlspecialchars', $formData)));
            return false;
        }

        if (!hash_equals($_SESSION[self::TOKEN_SESSION_KEY], $token)) {
            self::logReport("Token mismatch: data from an unknown source: " . json_encode(array_map('htmlspecialchars', $formData)));
            return false;
        }

        unset($_SESSION[self::TOKEN_SESSION_KEY]);
        unset($formData[self::TOKEN_SESSION_KEY]);

        return true;
    }

    /**
     * Insert a CSRF token input field into the form.
     */
    public static function insertCSRFInput(): void
    {
        $token = self::generateToken();
        $_SESSION[self::TOKEN_SESSION_KEY] = $token;
        $csrfTokenInputField = sprintf('<input type=hidden name=%s value=%s />', self::TOKEN_SESSION_KEY, $token);
        echo $csrfTokenInputField;
    }
}
