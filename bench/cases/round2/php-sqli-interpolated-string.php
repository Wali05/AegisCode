<?php
// expect: AEG-TAINT-SQL
$id = $_GET['id'];
$r = $pdo->query("SELECT * FROM t WHERE id = $id");
