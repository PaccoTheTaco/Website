<?php
session_start();
$db_config = include(__DIR__ . '/Secrets/db_config.php');

$conn = new mysqli($db_config['servername'], $db_config['username'], $db_config['password'], $db_config['dbname']);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$identifier = $_POST['identifier'];
$password = $_POST['password'];

// CSRF-Token Überprüfung
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("Invalid CSRF token");
}

// Bereiten Sie die Abfrage vor, um entweder den Benutzernamen oder die E-Mail-Adresse zu überprüfen
$stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ? OR email = ?");
$stmt->bind_param("ss", $identifier, $identifier);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $stmt->bind_result($user_id, $hashed_password);
    $stmt->fetch();

    if (password_verify($password, $hashed_password)) {
        session_regenerate_id(true); // Session Fixation verhindern
        $_SESSION['user_id'] = $user_id;
        echo "Login successful!";
        // Redirect to protected page or user dashboard
        // header("Location: dashboard.php");
    } else {
        echo "Invalid username/email or password.";
    }
} else {
    echo "Invalid username/email or password.";
}

$stmt->close();
$conn->close();
?>
