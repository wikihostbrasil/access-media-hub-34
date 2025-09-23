<?php
// Try to load Composer autoloader with fallback
$autoloader_path = __DIR__ . '/../vendor/autoload.php';
if (file_exists($autoloader_path)) {
    require_once $autoloader_path;
    use Firebase\JWT\JWT;
    use Firebase\JWT\Key;
} else {
    // If composer dependencies are not installed, use a simple JWT implementation
    // This is a fallback for development/testing
    class JWT {
        public static function encode($payload, $key, $alg = 'HS256') {
            $header = json_encode(['typ' => 'JWT', 'alg' => $alg]);
            $payload = json_encode($payload);
            
            $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
            $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
            
            $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $key, true);
            $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
            
            return $base64Header . "." . $base64Payload . "." . $base64Signature;
        }
        
        public static function decode($jwt, $key) {
            $parts = explode('.', $jwt);
            if (count($parts) != 3) {
                throw new Exception('Invalid JWT format');
            }
            
            list($base64Header, $base64Payload, $base64Signature) = $parts;
            
            $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $base64Header)), true);
            $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $base64Payload)), true);
            
            $signature = base64_decode(str_replace(['-', '_'], ['+', '/'], $base64Signature));
            $expectedSignature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $key->getKey(), true);
            
            if (!hash_equals($signature, $expectedSignature)) {
                throw new Exception('Invalid JWT signature');
            }
            
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                throw new Exception('JWT token expired');
            }
            
            return (object)$payload;
        }
    }
    
    class Key {
        private $key;
        private $algorithm;
        
        public function __construct($key, $algorithm) {
            $this->key = $key;
            $this->algorithm = $algorithm;
        }
        
        public function getKey() {
            return $this->key;
        }
        
        public function getAlgorithm() {
            return $this->algorithm;
        }
    }
}

class JWTHandler {
    private $secret_key;
    private $issuer = "arquivo-manager";
    private $audience = "arquivo-manager-users";
    private $issued_at;
    private $expiration_time;

    public function __construct() {
        $this->secret_key = $_ENV['JWT_SECRET'] ?? 'arquivo_manager_jwt_secret_key_default';
        $this->issued_at = time();
        $this->expiration_time = $this->issued_at + (24 * 60 * 60); // 24 hours - can be adjusted in /api/config/jwt.php line 16
    }

    public function createToken($user_id, $email, $role) {
        $payload = array(
            "iss" => $this->issuer,
            "aud" => $this->audience,
            "iat" => $this->issued_at,
            "exp" => $this->expiration_time,
            "data" => array(
                "id" => $user_id,
                "email" => $email,
                "role" => $role
            )
        );

        return JWT::encode($payload, $this->secret_key, 'HS256');
    }

    public function validateToken($token) {
        try {
            $decoded = JWT::decode($token, new Key($this->secret_key, 'HS256'));
            return (array) $decoded->data;
        } catch (Exception $e) {
            return false;
        }
    }

    public function getBearerToken() {
        $headers = $this->getAuthorizationHeader();
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }

    private function getAuthorizationHeader() {
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }
}
?>