<?php
    session_start(); 
    require 'config.php';

    if(isset($_POST["login_user"])){
        $user_input = trim($_POST['userName']); // Can be email or username
        $pass = trim($_POST['password']);

        // Use prepared statement to prevent SQL injection
        $sql = "SELECT id, username, email, password FROM customers WHERE email = ? OR username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $user_input, $user_input);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();

            // Verify password (assuming it's hashed)
            if (password_verify($pass, $row['password'])) { // Change 'password' if it's named differently
                $_SESSION['user'] = $row["id"];

                // Remember Me Feature
                if(!empty($_POST['remember'])) {
                    setcookie('user', $row["id"], time() + (86400 * 30), "/");
                }

                echo "<script> location.replace(\"dashboard.php\"); </script>";
                exit();
            } else {
                echo "<script>alert('Incorrect password'); location.replace(\"login.php\");</script>";
            }
        } else {
            echo "<script>alert('User not found'); location.replace(\"login.php\");</script>";
        }

        $stmt->close();
        $conn->close();
    }
?>
