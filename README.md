# PHPArmor - Secure Your PHP Applications

PHPAmor is a PHP module designed to enhance the security of your web applications by providing functionalities for handling Cross-Site Scripting (XSS), SQL Injection, and Cross-Site Request Forgery (CSRF). It also includes a simple database interaction layer for secure database operations.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [1. Set Log File Path](#1-set-log-file-path)
  - [2. Check Request for XSS and SQL Injection](#2-check-request-for-xss-and-sql-injection)
  - [3. Set Database Information](#3-set-database-information)
  - [4. Execute Database Queries](#4-execute-database-queries)
  - [5. CSRF Protection](#5-csrf-protection)

## Installation

You can install PHPAmor by cloning the GitHub repository into your project:

```bash
git clone https://github.com/imranrimi/PHPArmor.git
```

Then, include the `PHPArmor.php` file in your PHP project:

```php
require_once 'path/to/PHPArmor.php';
```

Alternatively, you can use Composer to include PHPAmor as a dependency. Add the following to your `composer.json` file:

```json
{
    "require": {
        "imranrimi/phparmor": "dev-main"
    },
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/imranrimi/PHPArmor.git"
        }
    ]
}
```

Then, run the following command:

```bash
composer install
```

Make sure to replace `'path/to/PHPArmor'` with the actual path to the PHPArmor library in your project.

Now, you can use PHPAmor in your project as described in the Usage section.


## Usage

### 1. Set Log File Path

Before using PHPAmor, you need to set the path for the log file where security issues will be recorded.

```php
$phpAmor = new PHPAmor();
$phpAmor->setLogFilePath('/path/to/security.log');
```

### 2. Check Request for XSS and SQL Injection

Use the `checkRequest` method to validate and sanitize user input to prevent XSS and SQL injection.

```php
$requestData = $_POST; // or $_GET, $_REQUEST, etc.

if ($phpAmor->checkRequest($requestData)) {
    // Proceed with the application logic
} else {
    // Handle the security threat
}
```

### 3. Set Database Information

Set the database information using the `setDBInformation` method before interacting with the database.

```php
$driver = 'mysql';
$host = 'localhost';
$database = 'mydatabase';
$username = 'root';
$password = 'password';

$phpAmor->setDBInformation($driver, $host, $database, $username, $password);
```

### 4. Execute Database Queries

Use the `execute` and `query` methods for secure database interactions.


### 4.1 `execute()` Method

The `execute()` method is used for executing prepared SQL statements. It provides a secure way to interact with the database, preventing SQL injection. Here's an explanation of its parameters:

- **Parameters:**
  - `$sql` (string): The SQL statement to be prepared and executed.
  - `$data` (array): An associative array containing parameter values to bind to the placeholders in the SQL statement.
  - `$fetchMode` (int|null): Optional. The PDO fetch mode to use when fetching the result set.
  - `$fetch` (string|null): Optional. The PDO fetch style to use when fetching the result set.

- **Usage Example:**
  ```php
  $sql = 'INSERT INTO users (username, email) VALUES (:username, :email)';
  $data = ['username' => 'john_doe', 'email' => 'john@example.com'];

  $phpAmor->execute($sql, $data);
  ```

   In this example, the execute() method is used to execute the provided SQL statement with the given data. It is suitable for INSERT, UPDATE, DELETE, SELECT, and other SQL operations that modify data. Additionally, it is designed to handle SQL queries that involve external data from users, and the method utilizes PHP's PDO prepare() method to avoid the possibility of a SQL injection attack. The use of prepared statements enhances security by ensuring that user-input data is properly sanitized and separated from the SQL query, preventing malicious SQL injection attempts.

### 2. `query()` Method

The `query()` method is used for executing simple SQL queries. It's suitable for SELECT statements or other queries that don't involve parameterized placeholders. Here's an explanation of its parameters:

- **Parameters:**
  - `$sql` (string): The SQL query to be executed.
  - `$fetchMode` (int|null): Optional. The PDO fetch mode to use when fetching the result set.
  - `$fetch` (string|null): Optional. The PDO fetch style to use when fetching the result set.

   **Usage Example:**

   ```php
   $sql = 'SELECT * FROM users WHERE username = "john_doe"';

   $result = $phpAmor->query($sql, \PDO::FETCH_OBJ, 'fetch');
   ```

   In this example, the `query()` method is used to execute the provided SELECT query. The result set is returned as an object of StdClass, and you can access the username as `$result->username`. This method is suitable for queries that retrieve data from the database and do not involve user-input data. It utilizes PHP's PDO `query()` method, providing a convenient way to fetch data as objects. Note that for queries involving user-input data, it is recommended to use the `execute()` method with prepared statements to mitigate the risk of SQL injection attacks.

### Additional Notes:

- Both `execute()` and `query()` methods handle database connections internally, providing a convenient interface for database interactions.
- The optional `$fetchMode` and `$fetch` parameters allow you to control how the result set is fetched. You can refer to [PDO documentation](https://www.php.net/manual/en/pdostatement.fetch.php) for possible values.

These methods help in building secure and maintainable database interactions by abstracting away the complexities of database access and providing protection against common security threats.
### 5. CSRF Protection

PHPAmor provides protection against CSRF attacks with token generation and validation.

#### Generate CSRF Token

Use `insertCSRFInput` to insert a hidden input field with a CSRF token into your HTML forms.

```php
PHPAmor::insertCSRFInput();
```
Certainly! Let's explain the "Generate CSRF Token" section and provide an example of inserting the CSRF token hidden field inside an HTML form.

### Generate CSRF Token

The `insertCSRFInput` method is used to generate a CSRF token and insert a hidden input field into HTML forms. This token helps protect against Cross-Site Request Forgery (CSRF) attacks by ensuring that form submissions come from a trusted source.

#### Usage Example:

```php
// Inside your PHP code, generate and insert the CSRF token in the HTML form
PHPAmor::insertCSRFInput();
```

This example demonstrates how to use the `insertCSRFInput` method within your PHP code to generate a CSRF token and insert it as a hidden input field in an HTML form.

#### HTML Form Example:

```html
<!-- Your HTML form -->
<form action="process_form.php" method="post">
    <!-- Other form fields go here -->

    <!-- Insert the CSRF token hidden field -->
    <?php PHPAmor::insertCSRFInput(); ?>

    <!-- Submit button -->
    <button type="submit">Submit Form</button>
</form>
```

In this HTML form example, the `PHPAmor::insertCSRFInput()` call generates a hidden input field with the CSRF token. When the form is submitted, this token is included in the form data. Upon form processing, you can then use the `validateCSRF` method to ensure the token's validity.

#### Validate CSRF Token

Ensure the CSRF token is present and valid in your form submission.

```php
$formData = $_POST; // Form submission data

if (PHPAmor::validateCSRF($formData)) {
    // Continue processing the form submission
} else {
    // Handle CSRF attack
}
```

## Contributing

Feel free to contribute to the development of PHPAmor by submitting issues or pull requests.

## License

This project is licensed under the [Apache License 2.0](LICENSE) - see the [LICENSE](LICENSE) file for details.


