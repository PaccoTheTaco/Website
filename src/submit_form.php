<?php
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $db_config = include(__DIR__ . '/Secrets/db_config.php');
    $encryption_config = include(__DIR__ . '/Secrets/encryption_config.php');

    $conn = new mysqli($db_config['servername'], $db_config['username'], $db_config['password'], $db_config['dbname']);

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // CSRF-Token Überprüfung
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid CSRF token");
    }

    $name = $conn->real_escape_string($_POST['name']);
    $title = $conn->real_escape_string($_POST['title']);
    $description = $conn->real_escape_string($_POST['description']);
    $email = $conn->real_escape_string($_POST['email']);

    $encryption_key = $encryption_config['encryption_key'];
    $iv = $encryption_config['iv'];

    $encrypted_email = openssl_encrypt($email, 'aes-256-cbc', $encryption_key, 0, $iv);

    $sql = "SELECT ticket_id FROM tickets ORDER BY id DESC LIMIT 1";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $last_ticket_id = $row['ticket_id'];
        list($prefix, $middle, $suffix) = explode('-', $last_ticket_id);
        $suffix = str_pad((int)$suffix + 1, 3, '0', STR_PAD_LEFT);
        $ticket_id = "$prefix-$middle-$suffix";
    } else {
        $ticket_id = "1402-001-001";
    }

    $ticket_active = 1;
    $stmt = $conn->prepare("INSERT INTO tickets (ticket_id, name, title, description, email, ticket_active) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssi", $ticket_id, $name, $title, $description, $encrypted_email, $ticket_active);

    if ($stmt->execute()) {
        echo "Ticket erfolgreich eingereicht! Ihre TicketID lautet: " . $ticket_id;
    } else {
        echo "Fehler: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
} else {
    die("Invalid request method");
}
?>
