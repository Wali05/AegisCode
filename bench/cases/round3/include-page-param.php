<?php
// expect: AEG-TAINT-PATH
$page = $_GET['page'];
include($page . ".php");
