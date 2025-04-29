<?php
// Run this once to insert the admin user
$pdo = new PDO("mysql:host=localhost;dbname=your_db", "your_user", "your_pass");

$username = "admin";
$password = "admin123";
$hash = password_hash($password, PASSWORD_DEFAULT);

$stmt = $pdo->prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)");
$stmt->execute([$username, $hash]);
?>
