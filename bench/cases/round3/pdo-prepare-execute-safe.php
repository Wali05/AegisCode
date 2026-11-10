<?php
// expect: none
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
echo json_encode($stmt->fetchAll());
