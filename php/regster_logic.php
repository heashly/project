<?php
session_start();
include('config.php'); // Include your database connection file

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = trim($_POST['email']);
    $userName = trim($_POST['userName']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    // Validate the form data
    if (empty($email) || empty($userName) || empty($password) || empty($confirm_password)) {
        $_SESSION['error'] = "All fields are required.";
        header("Location: register.php");
        exit();
    }

    // Check if passwords match
    if ($password !== $confirm_password) {
        $_SESSION['error'] = "Passwords do not match.";
        header("Location: register.php");
        exit();
    }

    // Check if the email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $_SESSION['error'] = "Email is already registered.";
        header("Location: register.php");
        exit();
    }

    // Hash the password
    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    // Prepare and execute the SQL query to insert the new user into the database
    $stmt = $conn->prepare("INSERT INTO users (userName, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $userName, $email, $password_hash);
    $stmt->execute();

    // Check if the user was registered successfully
    if ($stmt->affected_rows > 0) {
        $_SESSION['success'] = "Registration successful. You can now log in.";
        header("Location: login.php"); // Redirect to login page
        exit();
    } else {
        $_SESSION['error'] = "There was an error registering your account. Please try again.";
        header("Location: register.php");
        exit();
    }
}
?>
