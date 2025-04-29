<?php
session_start();
$mysqli = new mysqli("localhost", "root", "", "pilinut");

$error = "";
$success = "";

// Handle Login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["login"])) {
    $username = $_POST["username"];
    $password = $_POST["password"];

    $stmt = $mysqli->prepare("SELECT admin_id, password_hash FROM admins WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 1) {
        $stmt->bind_result($admin_id, $password_hash);
        $stmt->fetch();

        if (password_verify($password, $password_hash)) {
            $_SESSION["admin"] = true;
            $_SESSION["admin_id"] = $admin_id;
            header("Location: dashboard.php");
            exit();
        } else {
            $error = "Invalid password.";
        }
    } else {
        $error = "Admin not found.";
    }
    $stmt->close();
}

// Handle Registration
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["register"])) {
    $new_username = $_POST["new_username"];
    $new_password = $_POST["new_password"];
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

    $check_stmt = $mysqli->prepare("SELECT admin_id FROM admins WHERE username = ?");
    $check_stmt->bind_param("s", $new_username);
    $check_stmt->execute();
    $check_stmt->store_result();

    if ($check_stmt->num_rows > 0) {
        $error = "Username already taken.";
    } else {
        $insert_stmt = $mysqli->prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)");
        $insert_stmt->bind_param("ss", $new_username, $hashed_password);
        if ($insert_stmt->execute()) {
            $success = "Registration successful! You can now log in.";
        } else {
            $error = "Registration failed.";
        }
        $insert_stmt->close();
    }
    $check_stmt->close();
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - Pili Nuts Admin</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .hidden { display: none; }
        .toggle-link {
            text-align: center;
            margin-top: 10px;
            cursor: pointer;
            color: #007BFF;
            text-decoration: underline;
        }
    </style>
</head>
<body class="login-body">
    <div class="login-container">
        <h1 id="form-title">Pili Nuts Admin Login</h1>

        <!-- Login Form -->
        <form method="post" id="login-form">
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit" name="login">Login</button>
        </form>

        <!-- Register Form -->
        <form method="post" id="register-form" class="hidden">
            <input type="text" name="new_username" placeholder="New Username" required />
            <input type="password" name="new_password" placeholder="New Password" required />
            <button type="submit" name="register">Register</button>
        </form>

        <!-- Toggle links -->
        <div class="toggle-link" onclick="showRegister()">Don't have an account? Register here</div>
        <div class="toggle-link hidden" onclick="showLogin()">Already have an account? Login</div>

        <!-- Display error/success -->
        <?php
        if (!empty($error)) echo "<p class='error'>$error</p>";
        if (!empty($success)) echo "<p class='success'>$success</p>";
        ?>
    </div>

    <script>
        function showRegister() {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.remove('hidden');
            document.querySelector('h1#form-title').innerText = 'Register New Admin';
            document.querySelectorAll('.toggle-link')[0].classList.add('hidden'); // hide "Register here"
            document.querySelectorAll('.toggle-link')[1].classList.remove('hidden'); // show "Login"
        }

        function showLogin() {
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-form').classList.remove('hidden');
            document.querySelector('h1#form-title').innerText = 'Pili Nuts Admin Login';
            document.querySelectorAll('.toggle-link')[0].classList.remove('hidden'); // show "Register here"
            document.querySelectorAll('.toggle-link')[1].classList.add('hidden'); // hide "Login"
        }
    </script>
</body>
</html>
