<?php
// expect: AEG-TAINT-REDIRECT
header("Location: " . $_GET['url']);
exit;
