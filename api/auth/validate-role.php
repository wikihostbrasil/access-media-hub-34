<?php
include_once '../config/cors.php';
include_once '../config/database.php';
include_once '../config/jwt.php';
include_once '../config/security.php';

$database = new Database();
$db = $database->getConnection();
$jwt = new JWTHandler();

// Validate token
$token = $jwt->getBearerToken();
if (!$token) {
    http_response_code(401);
    echo json_encode(array("error" => "Token não fornecido"));
    exit();
}

$user_data = $jwt->validateToken($token);
if (!$user_data) {
    http_response_code(401);
    echo json_encode(array("error" => "Token inválido"));
    exit();
}

try {
    // Get current user data from database (source of truth)
    $query = "SELECT u.id, u.email, u.active, p.full_name, p.role 
              FROM users u 
              LEFT JOIN profiles p ON u.id = p.user_id 
              WHERE u.id = :user_id";
    $stmt = $db->prepare($query);
    $stmt->bindParam(":user_id", $user_data['id']);
    $stmt->execute();
    
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(array("error" => "Usuário não encontrado"));
        exit();
    }
    
    if (!$user['active']) {
        http_response_code(403);
        echo json_encode(array("error" => "Usuário inativo"));
        exit();
    }
    
    // Return current user role and data from database
    http_response_code(200);
    echo json_encode(array(
        "id" => $user['id'],
        "email" => $user['email'],
        "full_name" => $user['full_name'] ?? $user['email'],
        "role" => $user['role'] ?? 'user'
    ));
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(array("error" => "Erro interno do servidor"));
}
?>