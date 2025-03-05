<?php
    session_start();
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (!isset($_SESSION["token"]) || $_POST["token"] !== $_SESSION["token"]) {
            die("CSRF detected. Invalid token.");
        }
        echo("Form submitted!");
    }
    $_SESSION["token"] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Electra CSRF Website</title>
</head>
<body>
    <h2>Login</h2>
    <form action="index.php" method="post">
        <label>Username:</label>
        <input type="text" name="username" required>
        <br>
        <label>Password:</label>
        <input type="password" name="password" required>
        <br>
        <input type="hidden" name="token" value="<?php echo $_SESSION['token'];?>">
        <button type="submit">Submit</button>
    </form>
    <script>
        var token = "<?php echo $_SESSION['token']; ?>";
        console.log("JS-based CSRF token:", token);
    </script>

    <h2>AJAX Request</h2>
    <button onclick="submitAjax()">Submit AJAX</button>
    <script>
        function submitAjax() {
            fetch("ajax.php", {
                method: "POST",
                headers: {"Content-Type": "application/x-www-form-urlencoded"},
                body: "token=" + token
            })
            .then(response => response.text())
            .then(data => alert("Response: " + data));
        }
    </script>
</body>
</html>