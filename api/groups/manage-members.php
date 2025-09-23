<?php
include_once '../config/cors.php';
include_once '../config/database.php';
include_once '../config/jwt.php';
include_once '../config/security.php';
include_once '../config/auth-security.php';

$database = new Database();
$db = $database->getConnection();
$jwt = new JWTHandler();
$auth_security = new AuthSecurity($db);

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

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Get group members
    $group_id = $_GET['group_id'] ?? null;
    
    if (!$group_id) {
        http_response_code(400);
        echo json_encode(array("error" => "ID do grupo é obrigatório"));
        exit();
    }
    
    try {
        // Check if user can view this group
        $check_query = "SELECT created_by FROM groups WHERE id = :id";
        $check_stmt = $db->prepare($check_query);
        $check_stmt->bindParam(":id", $group_id);
        $check_stmt->execute();
        $group = $check_stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$group) {
            http_response_code(404);
            echo json_encode(array("error" => "Grupo não encontrado"));
            exit();
        }
        
        // Only admin or group creator can view members
        $auth_security->canModifyResource($user_data['id'], $group['created_by'], 'view_group_members');
        
        $query = "SELECT p.user_id, p.full_name, p.role, u.email 
                  FROM user_groups ug 
                  JOIN profiles p ON ug.user_id = p.user_id 
                  JOIN users u ON p.user_id = u.id 
                  WHERE ug.group_id = :group_id AND p.active = true
                  ORDER BY p.full_name";
        $stmt = $db->prepare($query);
        $stmt->bindParam(":group_id", $group_id);
        $stmt->execute();
        
        $members = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        http_response_code(200);
        echo json_encode($members);
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(array("error" => "Erro ao buscar membros do grupo"));
    }
    
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Add/remove members
    $data = json_decode(file_get_contents("php://input"), true);
    
    if (!$data || !isset($data['group_id']) || !isset($data['user_ids'])) {
        http_response_code(400);
        echo json_encode(array("error" => "Dados obrigatórios não fornecidos"));
        exit();
    }
    
    $group_id = $data['group_id'];
    $user_ids = $data['user_ids'];
    $action = $data['action'] ?? 'set'; // 'set', 'add', 'remove'
    
    try {
        // Check if user can modify this group
        $check_query = "SELECT created_by FROM groups WHERE id = :id";
        $check_stmt = $db->prepare($check_query);
        $check_stmt->bindParam(":id", $group_id);
        $check_stmt->execute();
        $group = $check_stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$group) {
            http_response_code(404);
            echo json_encode(array("error" => "Grupo não encontrado"));
            exit();
        }
        
        // Only admin or group creator can manage members
        $auth_security->canModifyResource($user_data['id'], $group['created_by'], 'manage_group_members');
        
        // Check rate limiting
        $auth_security->checkCriticalRateLimit($user_data['id'], 'manage_group_members', 10, 60);
        
        $db->beginTransaction();
        
        if ($action === 'set') {
            // Remove all current members and add new ones
            $delete_query = "DELETE FROM user_groups WHERE group_id = :group_id";
            $delete_stmt = $db->prepare($delete_query);
            $delete_stmt->bindParam(":group_id", $group_id);
            $delete_stmt->execute();
        }
        
        if ($action === 'set' || $action === 'add') {
            // Add new members
            foreach ($user_ids as $user_id) {
                if ($action === 'add') {
                    // Check if already exists
                    $check_query = "SELECT 1 FROM user_groups WHERE group_id = :group_id AND user_id = :user_id";
                    $check_stmt = $db->prepare($check_query);
                    $check_stmt->bindParam(":group_id", $group_id);
                    $check_stmt->bindParam(":user_id", $user_id);
                    $check_stmt->execute();
                    
                    if ($check_stmt->fetch()) {
                        continue; // Skip if already exists
                    }
                }
                
                $insert_query = "INSERT INTO user_groups (group_id, user_id, created_at) VALUES (:group_id, :user_id, NOW())";
                $insert_stmt = $db->prepare($insert_query);
                $insert_stmt->bindParam(":group_id", $group_id);
                $insert_stmt->bindParam(":user_id", $user_id);
                $insert_stmt->execute();
            }
        } else if ($action === 'remove') {
            // Remove specific members
            foreach ($user_ids as $user_id) {
                $remove_query = "DELETE FROM user_groups WHERE group_id = :group_id AND user_id = :user_id";
                $remove_stmt = $db->prepare($remove_query);
                $remove_stmt->bindParam(":group_id", $group_id);
                $remove_stmt->bindParam(":user_id", $user_id);
                $remove_stmt->execute();
            }
        }
        
        $db->commit();
        
        // Log the action
        $security_logger = new SecurityLogger($db);
        $security_logger->logSecurityEvent('group_members_updated', $_SERVER['REMOTE_ADDR'], $user_data['id'], "Updated members for group: $group_id");
        
        http_response_code(200);
        echo json_encode(array("message" => "Membros do grupo atualizados com sucesso"));
        
    } catch (Exception $e) {
        $db->rollback();
        http_response_code(500);
        echo json_encode(array("error" => "Erro ao atualizar membros do grupo"));
    }
}
?>