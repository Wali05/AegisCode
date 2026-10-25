<?php
// expect: AEG-TAINT-PATH
$page = $_GET['page'];
include("pages/" . $page . ".php");
