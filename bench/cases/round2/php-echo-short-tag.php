<?php
// expect: AEG-TAINT-XSS
?>
<h1><?= $_GET['name'] ?></h1>
