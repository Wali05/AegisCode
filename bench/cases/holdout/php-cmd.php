<?php
// expect: AEG-TAINT-CMD
$host = $_GET['host'];
$out = shell_exec("nslookup " . $host);
