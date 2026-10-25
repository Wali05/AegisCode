<?php
// expect: AEG-TAINT-XSS
echo "<h1>Hello " . $_GET['name'] . "</h1>";
