<?php
// expect: AEG-TAINT-SQL
$r = $pdo->query("SELECT * FROM t WHERE id = {$_GET['id']}");
