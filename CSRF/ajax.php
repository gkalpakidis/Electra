<?php
    session_start();
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        if (!isset($_POST["token"]) || $_POST["token"] !== $_SESSION["token"]) {
            die("CSRF detected. AJAX request blocked.");
        }
        echo("Successful AJAX request.");
    }
?>