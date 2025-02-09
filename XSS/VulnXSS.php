<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnXSS</title>
</head>
<body>
    <h1>VulnXSS Website</h1>
    <!--Reflected XSS-->
    <form action="" method="get">
        <label for="search">Search:</label>
        <input type="text" name="q" id="search">
        <input type="submit" value="Search">
    </form>
    <!--
    <p>
        Search Result: <span id="search-result">%QUERY%</span>
    </p>
    -->
    <?php
        if (isset($_GET['q'])) {
            echo("<h3>Search results for: " . $_GET['q'] . "</h3>");
        }
    ?>

    <br>
    
    <!--Stored XSS-->
    <form action="" method="post">
        <label for="comment">Comment Us!</label>
        <input type="text" name="comment" id="comment">
        <!--<textarea name="comment-text"></textarea>-->
        <input type="submit" value="Post">
    </form>
    <!--
    <h3>Comments:</h3>
    <div id="comments">%COMMENTS%</div>
    -->
    <?php
        $file = "comments.txt";
        if (isset($_POST['comment'])) {
            file_put_contents($file, $_POST['comment'] . "\n", FILE_APPEND);
        }
        if (file_exists($file)) {
            echo("<h3>Comments:</h3>");
            echo(nl2br(file_get_contents($file)));
        }
    ?>

    <!--DOM-based XSS-->
    <p>
        DOM-based XSS Test: <span id="dom-based"></span>
    </p>
    <script>
        document.getElementById("dom-based").innerHTML = location.hash.substring(1);
    </script>

    <!--Header-based XSS-->
    <!--
    <p>User-Agent: %USER_AGENT%</p>
    <p>Referer: %REFERER%</p>
    -->
    <?php
        echo("<p>User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "</p>");
        echo("<p>Referer: " . ($_SERVER['HTTP_REFERER'] ?? 'None') . "</p>");
    ?>
</body>
</html>