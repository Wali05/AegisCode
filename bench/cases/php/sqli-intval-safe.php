<?php
// expect: none
$id = intval($_GET['id']);
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
