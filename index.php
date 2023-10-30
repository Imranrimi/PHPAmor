<?php
require_once('PHPAmor.php');

echo "<h1 style='text-align: center; padding:10rem; font-size:5rem; font-weight:900'>Amor Testing</h1>";

$amor = new PHPAmor();

$amor = $amor->setDBInformation("mysql","localhost","testing","root","");
$amor = $amor->setLogFilePath("logs.log");

// Simulate a GET request with test data
$_GET = array(
    'username' => 'john_doe',
    'search' => '<script>alert("XSS");</script>',
    'page' => 1,
);

// Simulate a POST request with test data
$_POST = array(
    'user_input' => 'This is a safe input.',
    'comment' => 'A potentially harmful <script>alert("XSS");</script> comment.',
    'action' => 'submit',
);

// database insertion data
$userData = [
    'id' => 1,
    'name' => 'john_doe',
    'dept' => "password\'; DELETE FROM test;",
    'score' => 98,
    'age' => 23
];
$sql2 = 'SELECT * FROM users WHERE username = "john_doe" OR 1=1 --';
$sql = 'INSERT INTO test(id, name, dept, age, score) VALUES(:id, :name, :dept, :score, :age)';
$insert = $amor->query($sql2);
var_dump($insert);
exit;
// Example usage:


