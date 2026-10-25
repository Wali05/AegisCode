<?php
// expect: AEG-TAINT-SQL
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
