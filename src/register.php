<?php
session_start();
$db_config = include(__DIR__ . '/Secrets/db_config.php');

$conn = new mysqli($db_config['servername'], $db_config['username'], $db_config['password'], $db_config['dbname']);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$username = $_POST['username'];
$email = $_POST['email'];
$password = $_POST['password'];

// CSRF-Token Überprüfung
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("Invalid CSRF token");
}

// Überprüfen, ob der Benutzername oder die E-Mail bereits existieren
$stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
$stmt->bind_param("ss", $username, $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    echo "Username or email already exists.";
    $stmt->close();
    $conn->close();
    exit();
}

$hashed_password = password_hash($password, PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $username, $email, $hashed_password);

if ($stmt->execute()) {
    echo "Registration successful!";
} else {
    echo "Error: " . $stmt->error;
}

$stmt->close();
$conn->close();
?>
