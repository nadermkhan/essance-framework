<?php
/**
 * Essance Framework v1.0.0
 * A lightweight, single-file PHP framework to modernize legacy projects
 * 
 * @author Nader Mahbub Khan
 * @version 1.0.0
 * @license MIT
 */

namespace Essance;

// Framework version
define('ESSANCE_VERSION', '1.0.0');


/**
 * Environment Configuration Manager
 */
class Env {
    private static $variables = [];
    private static $loaded = false;

    public static function load($path = '.env') {
        if (self::$loaded) return;
        
        $envFile = dirname($_SERVER['SCRIPT_FILENAME']) . '/' . $path;
        if (!file_exists($envFile)) {
            self::createDefault($envFile);
        }
        
        $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value, '"\'');
            
            self::$variables[$name] = $value;
            putenv("$name=$value");
            $_ENV[$name] = $value;
        }
        self::$loaded = true;
    }

    public static function get($key, $default = null) {
        return self::$variables[$key] ?? $_ENV[$key] ?? getenv($key) ?: $default;
    }

    private static function createDefault($path) {
        $default = "# Essance Framework Environment Configuration\n";
        $default .= "# Version: " . ESSANCE_VERSION . "\n\n";
        $default .= "APP_NAME=Essance\n";
        $default .= "APP_ENV=production\n";
        $default .= "APP_DEBUG=false\n";
        $default .= "APP_URL=http://localhost\n";
        $default .= "APP_TIMEZONE=UTC\n\n";
        $default .= "# Upload Configuration\n";
        $default .= "UPLOAD_MAX_SIZE=10485760\n";
        $default .= "UPLOAD_CHUNK_SIZE=1048576\n";
        $default .= "UPLOAD_ALLOWED_TYPES=jpg,jpeg,png,gif,pdf,doc,docx,zip\n\n";
        $default .= "# Cache Configuration\n";
        $default .= "CACHE_ENABLED=true\n";
        $default .= "CACHE_LIFETIME=3600\n";
        file_put_contents($path, $default);
    }
}

/**
 * Router Class - Handles all routing logic
 */
class Router {
    private static $routes = [];
    private static $namedRoutes = [];
    private static $currentRoute = null;
    private static $middleware = [];
    private static $groupPrefix = '';
    private static $groupMiddleware = [];
    
    public static function get($path, $callback, $name = null) {
        self::addRoute('GET', $path, $callback, $name);
    }
    
    public static function post($path, $callback, $name = null) {
        self::addRoute('POST', $path, $callback, $name);
    }
    
    public static function put($path, $callback, $name = null) {
        self::addRoute('PUT', $path, $callback, $name);
    }
    
    public static function delete($path, $callback, $name = null) {
        self::addRoute('DELETE', $path, $callback, $name);
    }
    
    public static function patch($path, $callback, $name = null) {
        self::addRoute('PATCH', $path, $callback, $name);
    }
    
    public static function any($path, $callback, $name = null) {
        self::addRoute('ANY', $path, $callback, $name);
    }
    
    public static function group($prefix, $callback, $middleware = []) {
        $previousPrefix = self::$groupPrefix;
        $previousMiddleware = self::$groupMiddleware;
        
        self::$groupPrefix = $previousPrefix . $prefix;
        self::$groupMiddleware = array_merge($previousMiddleware, (array)$middleware);
        
        call_user_func($callback);
        
        self::$groupPrefix = $previousPrefix;
        self::$groupMiddleware = $previousMiddleware;
    }
    
    private static function addRoute($method, $path, $callback, $name = null) {
        $path = self::$groupPrefix . $path;
        $route = [
            'method' => $method,
            'path' => $path,
            'callback' => $callback,
            'regex' => self::buildRegex($path),
            'params' => self::extractParams($path),
            'middleware' => self::$groupMiddleware
        ];
        
        self::$routes[] = $route;
        
        if ($name) {
            self::$namedRoutes[$name] = $route;
        }
    }
    
    private static function buildRegex($path) {
        // Support for optional parameters
        $regex = preg_replace('/\{([a-zA-Z0-9_]+)\?\}/', '(?:([a-zA-Z0-9_-]+))?', $path);
        // Support for regular parameters
        $regex = preg_replace('/\{([a-zA-Z0-9_]+)\}/', '([a-zA-Z0-9_-]+)', $regex);
        // Support for wildcard parameters
        $regex = preg_replace('/\{([a-zA-Z0-9_]+):\*\}/', '(.+)', $regex);
        return '#^' . $regex . '$#';
    }
    
    private static function extractParams($path) {
        preg_match_all('/\{([a-zA-Z0-9_]+)(\?|:\*)?\}/', $path, $matches);
        return $matches[1];
    }
    
    public static function dispatch() {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $uri = rtrim($uri, '/') ?: '/';

        // Remove base path if in subdirectory
        $scriptName = dirname($_SERVER['SCRIPT_NAME']);
        if ($scriptName !== '/' && $scriptName !== '\\') {
            if (strpos($uri, $scriptName) === 0) {
                $uri = substr($uri, strlen($scriptName));
            }
        }
        $uri = rtrim($uri, '/') ?: '/';
        foreach (self::$routes as $route) {
            if ($route['method'] !== 'ANY' && $route['method'] !== $method) {
                continue;
            }
            
            if (preg_match($route['regex'], $uri, $matches)) {
                array_shift($matches);
                $params = [];
                foreach ($route['params'] as $index => $param) {
                    $params[$param] = $matches[$index] ?? null;
                }
                
                self::$currentRoute = $route;
                $request = new Request($params);
                
                // Execute route middleware
                foreach ($route['middleware'] as $middleware) {
                    $result = self::executeMiddleware($middleware, $request);
                    if ($result === false) return;
                }
                
                // Execute global middleware
                foreach (self::$middleware as $middleware) {
                    $result = self::executeMiddleware($middleware, $request);
                    if ($result === false) return;
                }
                
                // Execute callback
                if (is_string($route['callback']) && strpos($route['callback'], '@') !== false) {
                    list($controller, $method) = explode('@', $route['callback']);
                    if (!class_exists($controller)) {
                        $controller = "\\App\\Controllers\\$controller";
                    }
                    $controllerInstance = new $controller();
                    return call_user_func_array([$controllerInstance, $method], [$request]);
                }
                
                return call_user_func($route['callback'], $request);
            }
        }
        
        self::notFound();
    }
    
    private static function executeMiddleware($middleware, $request) {
        if (is_string($middleware) && class_exists($middleware)) {
            $middleware = new $middleware();
            return $middleware->handle($request);
        }
        return call_user_func($middleware, $request);
    }
    
    public static function middleware($callback) {
        self::$middleware[] = $callback;
    }
    
    public static function notFound($callback = null) {
        if ($callback !== null) {
            return call_user_func($callback);
        }
        
        http_response_code(404);
        $html = '<!DOCTYPE html>
<html>
<head>
    <title>404 - Page Not Found</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               color: white; display: flex; align-items: center; justify-content: center; 
               height: 100vh; margin: 0; }
        .container { text-align: center; }
        h1 { font-size: 120px; margin: 0; opacity: 0.9; }
        h2 { font-size: 32px; margin: 10px 0 20px; opacity: 0.95; }
        p { font-size: 18px; opacity: 0.9; }
        a { color: white; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you are looking for doesn\'t exist.</p>
        <p><a href="/">Go Home</a></p>
        <p style="margin-top: 40px; font-size: 12px; opacity: 0.7;">Powered by Essance Framework v' . ESSANCE_VERSION . '</p>
    </div>
</body>
</html>';
        echo $html;
    }
    
    public static function url($name, $params = []) {
        if (!isset(self::$namedRoutes[$name])) {
            return '#';
        }
        
        $route = self::$namedRoutes[$name];
        $url = $route['path'];
        
        foreach ($params as $key => $value) {
            $url = str_replace('{' . $key . '}', $value, $url);
            $url = str_replace('{' . $key . '?}', $value, $url);
        }
        
        // Remove optional parameters that weren't provided
        $url = preg_replace('/\{[a-zA-Z0-9_]+\?\}/', '', $url);
        
        return $url;
    }
    
    public static function getCurrentRoute() {
        return self::$currentRoute;
    }
}

/**
 * Request Class - Handles HTTP request data
 */
class Request {
    public $params;
    public $query;
    public $post;
    public $files;
    public $headers;
    public $method;
    public $uri;
    public $ip;
    public $ajax;
    public $secure;
    public $json;
    
    public function __construct($params = []) {
        $this->params = $params;
        $this->query = $_GET;
        $this->post = $_POST;
        $this->files = $_FILES;
        $this->headers = $this->getAllHeaders();
        $this->method = $_SERVER['REQUEST_METHOD'];
        $this->uri = $_SERVER['REQUEST_URI'];
        $this->ip = $this->getClientIp();
        $this->ajax = $this->isAjax();
        $this->secure = $this->isSecure();
        $this->json = $this->parseJson();
    }
    
      /**
     * Get a parameter value by key
     * Returns null if the parameter doesn't exist
     * 
     * @param string $key
     * @return mixed|null
     */
    public function paramValue($key) {
        return $this->params[$key] ?? null;
    }
    
    /**
     * Get a parameter value by key with a default fallback
     * 
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function paramValueOr($key, $default = null) {
        return $this->params[$key] ?? $default;
    }
    
    /**
     * Alias for paramValue for shorter syntax
     * 
     * @param string $key
     * @return mixed|null
     */
    public function param($key) {
        return $this->paramValue($key);
    }
    
    /**
     * Check if a parameter exists
     * 
     * @param string $key
     * @return bool
     */
    public function hasParam($key) {
        return isset($this->params[$key]);
    }
    
    /**
     * Get all parameters
     * 
     * @return array
     */
    public function params() {
        return $this->params;
    }
    
    
    public function input($key, $default = null) {
        return $this->post[$key] ?? $this->query[$key] ?? $this->json[$key] ?? $default;
    }
    
    public function all() {
        return array_merge($this->query, $this->post, $this->json ?? [], $this->params);
    }
    
    public function only($keys) {
        $keys = is_array($keys) ? $keys : func_get_args();
        return array_intersect_key($this->all(), array_flip($keys));
    }
    
    public function except($keys) {
        $keys = is_array($keys) ? $keys : func_get_args();
        return array_diff_key($this->all(), array_flip($keys));
    }
    
    public function has($key) {
        return isset($this->post[$key]) || isset($this->query[$key]) || 
               isset($this->params[$key]) || isset($this->json[$key]);
    }
    
    public function filled($key) {
        $value = $this->input($key);
        return $value !== null && $value !== '';
    }
    
    public function isAjax() {
        return !empty($this->headers['X-Requested-With']) && 
               strtolower($this->headers['X-Requested-With']) === 'xmlhttprequest';
    }
    
    public function isJson() {
        return strpos($this->headers['Content-Type'] ?? '', 'application/json') !== false;
    }
    
    public function isSecure() {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || 
               $_SERVER['SERVER_PORT'] == 443;
    }
    
    public function bearerToken() {
        $header = $this->headers['Authorization'] ?? '';
        if (preg_match('/Bearer\s+(.+)/', $header, $matches)) {
            return $matches[1];
        }
        return null;
    }
    
    private function parseJson() {
        if ($this->isJson()) {
            $content = file_get_contents('php://input');
            return json_decode($content, true) ?: [];
        }
        return [];
    }
    
    private function getAllHeaders() {
        if (function_exists('getallheaders')) {
            return getallheaders();
        }
        
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
    
    private function getClientIp() {
        $keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }
    
    public function validate($rules) {
        $errors = [];
        foreach ($rules as $field => $rule) {
            $value = $this->input($field);
            $fieldRules = explode('|', $rule);
            
            foreach ($fieldRules as $fieldRule) {
                if ($fieldRule === 'required' && empty($value)) {
                    $errors[$field][] = "The $field field is required.";
                }
                if (strpos($fieldRule, 'min:') === 0) {
                    $min = (int)substr($fieldRule, 4);
                    if (strlen($value) < $min) {
                        $errors[$field][] = "The $field must be at least $min characters.";
                    }
                }
                if (strpos($fieldRule, 'max:') === 0) {
                    $max = (int)substr($fieldRule, 4);
                    if (strlen($value) > $max) {
                        $errors[$field][] = "The $field must not exceed $max characters.";
                    }
                }
                if ($fieldRule === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $errors[$field][] = "The $field must be a valid email address.";
                }
                if ($fieldRule === 'numeric' && !is_numeric($value)) {
                    $errors[$field][] = "The $field must be numeric.";
                }
            }
        }
        return empty($errors) ? true : $errors;
    }
}

/**
 * Response Class - Handles HTTP responses
 */
class Response {
    private static $statusTexts = [
        200 => 'OK',
        201 => 'Created',
        204 => 'No Content',
        301 => 'Moved Permanently',
        302 => 'Found',
        304 => 'Not Modified',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        500 => 'Internal Server Error',
        503 => 'Service Unavailable'
    ];
    
    public static function json($data, $status = 200, $options = JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, $options);
        exit;
    }
    
    public static function html($content, $status = 200) {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        echo $content;
        exit;
    }
    
    public static function text($content, $status = 200) {
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        echo $content;
        exit;
    }
    
    public static function xml($content, $status = 200) {
        http_response_code($status);
        header('Content-Type: application/xml; charset=utf-8');
        echo $content;
        exit;
    }
    
    public static function redirect($url, $status = 302) {
        http_response_code($status);
        header("Location: $url");
        exit;
    }
    
    public static function back() {
        $referer = $_SERVER['HTTP_REFERER'] ?? '/';
        self::redirect($referer);
    }
    
    public static function download($file, $name = null) {
        if (!file_exists($file)) {
            http_response_code(404);
            exit;
        }
        
        $name = $name ?: basename($file);
        $size = filesize($file);
        $mime = mime_content_type($file);
        
        header("Content-Type: $mime");
        header("Content-Disposition: attachment; filename=\"$name\"");
        header("Content-Length: $size");
        header("Cache-Control: no-cache, must-revalidate");
        header("Pragma: no-cache");
        header("Expires: 0");
        
        readfile($file);
        exit;
    }
    
    public static function stream($file, $name = null) {
        if (!file_exists($file)) {
            http_response_code(404);
            exit;
        }
        
        $name = $name ?: basename($file);
        $size = filesize($file);
        $mime = mime_content_type($file);
        
        header("Content-Type: $mime");
        header("Content-Disposition: inline; filename=\"$name\"");
        header("Content-Length: $size");
        header("Accept-Ranges: bytes");
        
        readfile($file);
        exit;
    }
    
    public static function view($file, $data = []) {
        if (!file_exists($file)) {
            throw new \Exception("View file not found: $file");
        }
        
        extract($data);
        ob_start();
        include $file;
        $content = ob_get_clean();
        self::html($content);
    }
    
    public static function error($message, $status = 400) {
        self::json(['error' => $message], $status);
    }
    
    public static function success($data = null, $message = 'Success') {
        self::json(['success' => true, 'message' => $message, 'data' => $data]);
    }
}

/**
 * Controller Base Class
 */
abstract class Controller {
    protected $request;
    
    public function __construct() {
        $this->request = new Request();
    }
    
    protected function json($data, $status = 200) {
        return Response::json($data, $status);
    }
    
    protected function view($file, $data = []) {
        return Response::view($file, $data);
    }
    
    protected function redirect($url, $status = 302) {
        return Response::redirect($url, $status);
    }
    
    protected function back() {
        return Response::back();
    }
    
    protected function success($data = null, $message = 'Success') {
        return Response::success($data, $message);
    }
    
    protected function error($message, $status = 400) {
        return Response::error($message, $status);
    }
}

/**
 * ChunkUpload Class - Handles chunked file uploads
 */
class ChunkUpload {
    private $uploadDir;
    private $tempDir;
    private $maxSize;
    private $chunkSize;
    private $allowedExtensions;
    private $allowedMimeTypes;
    
    public function __construct($uploadDir = 'uploads', $tempDir = 'temp') {
        $this->uploadDir = rtrim($uploadDir, '/');
        $this->tempDir = rtrim($tempDir, '/');
        $this->maxSize = (int)Env::get('UPLOAD_MAX_SIZE', 10485760);
        $this->chunkSize = (int)Env::get('UPLOAD_CHUNK_SIZE', 1048576);
        
        $extensions = Env::get('UPLOAD_ALLOWED_TYPES', 'jpg,jpeg,png,gif,pdf');
        $this->allowedExtensions = explode(',', $extensions);
        
        $this->allowedMimeTypes = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'application/zip', 'application/x-zip-compressed',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain', 'text/csv'
        ];
        
        $this->createDirs();
    }
    
    private function createDirs() {
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0755, true);
        }
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0755, true);
        }
        
        // Create index.html to prevent directory listing
        $indexContent = '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><p>Directory access is forbidden.</p></body></html>';
        
        if (!file_exists($this->uploadDir . '/index.html')) {
            file_put_contents($this->uploadDir . '/index.html', $indexContent);
        }
        if (!file_exists($this->tempDir . '/index.html')) {
            file_put_contents($this->tempDir . '/index.html', $indexContent);
        }
    }
    
    public function setAllowedExtensions($extensions) {
        $this->allowedExtensions = $extensions;
        return $this;
    }
    
    public function setAllowedMimeTypes($types) {
        $this->allowedMimeTypes = $types;
        return $this;
    }
    
    public function setMaxSize($size) {
        $this->maxSize = $size;
        return $this;
    }
    
    public function handleChunk($request) {
        $fileName = $request->input('fileName');
        $chunkIndex = (int)$request->input('chunkIndex', 0);
        $totalChunks = (int)$request->input('totalChunks', 1);
        $identifier = $request->input('identifier', uniqid());
        
        if (!$fileName) {
            return ['success' => false, 'error' => 'File name is required'];
        }
        
        // Validate extension
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if (!in_array($ext, $this->allowedExtensions)) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }
        
        $tempFile = $this->tempDir . '/' . $identifier . '.part';
        $chunkData = file_get_contents('php://input');
        
        if ($chunkIndex === 0) {
            // First chunk - validate mime type
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mimeType = finfo_buffer($finfo, $chunkData);
            finfo_close($finfo);
            
            if (!in_array($mimeType, $this->allowedMimeTypes)) {
                return ['success' => false, 'error' => 'Invalid file type'];
            }
            
            file_put_contents($tempFile, $chunkData);
        } else {
            file_put_contents($tempFile, $chunkData, FILE_APPEND | LOCK_EX);
        }
        
        // Check if all chunks received
        if ($chunkIndex === $totalChunks - 1) {
            $fileSize = filesize($tempFile);
            
            if ($fileSize > $this->maxSize) {
                unlink($tempFile);
                return ['success' => false, 'error' => 'File size exceeds maximum allowed'];
            }
            
            $finalName = $this->generateFileName($fileName);
            $finalPath = $this->uploadDir . '/' . $finalName;
            
            if (rename($tempFile, $finalPath)) {
                return [
                    'success' => true,
                    'completed' => true,
                    'fileName' => $finalName,
                    'originalName' => $fileName,
                    'path' => $finalPath,
                    'url' => '/' . $this->uploadDir . '/' . $finalName,
                    'size' => $fileSize,
                    'sizeFormatted' => $this->formatBytes($fileSize)
                ];
            }
            
            return ['success' => false, 'error' => 'Failed to save file'];
        }
        
        return [
            'success' => true,
            'completed' => false,
            'chunk' => $chunkIndex,
            'totalChunks' => $totalChunks,
            'identifier' => $identifier
        ];
    }
    
    public function handleSimple($file) {
        if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'error' => $this->getUploadError($file['error'] ?? UPLOAD_ERR_NO_FILE)];
        }
        
        if ($file['size'] > $this->maxSize) {
            return ['success' => false, 'error' => 'File size exceeds maximum allowed'];
        }
        
        // Validate extension
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, $this->allowedExtensions)) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }
        
        // Validate mime type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mimeType, $this->allowedMimeTypes)) {
            return ['success' => false, 'error' => 'Invalid file type'];
        }
        
        $finalName = $this->generateFileName($file['name']);
        $finalPath = $this->uploadDir . '/' . $finalName;
        
        if (move_uploaded_file($file['tmp_name'], $finalPath)) {
            return [
                'success' => true,
                'fileName' => $finalName,
                'originalName' => $file['name'],
                'path' => $finalPath,
                'url' => '/' . $this->uploadDir . '/' . $finalName,
                'size' => $file['size'],
                'sizeFormatted' => $this->formatBytes($file['size']),
                'mimeType' => $mimeType
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to save file'];
    }
    
    public function delete($fileName) {
        $filePath = $this->uploadDir . '/' . basename($fileName);
        
        if (file_exists($filePath) && is_file($filePath)) {
            if (unlink($filePath)) {
                return ['success' => true, 'message' => 'File deleted successfully'];
            }
        }
        
        return ['success' => false, 'error' => 'File not found or could not be deleted'];
    }
    
    private function generateFileName($originalName) {
        $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        $baseName = pathinfo($originalName, PATHINFO_FILENAME);
        $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $baseName);
        $safeName = substr($safeName, 0, 50);
        
        return $safeName . '_' . uniqid() . '_' . time() . '.' . $ext;
    }
    
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
    
    private function getUploadError($code) {
        $errors = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
        ];
        
        return $errors[$code] ?? 'Unknown upload error';
    }
    
    public function cleanup($hours = 24) {
        $files = glob($this->tempDir . '/*.part');
        $now = time();
        $count = 0;
        
        foreach ($files as $file) {
            if ($now - filemtime($file) > ($hours * 3600)) {
                if (unlink($file)) {
                    $count++;
                }
            }
        }
        
        return $count;
    }
}

/**
 * Cache Class - Simple file-based caching
 */
class Cache {
    private static $cacheDir = 'cache';
    private static $enabled = true;
    
    public static function init($dir = 'cache') {
        self::$cacheDir = rtrim($dir, '/');
        self::$enabled = Env::get('CACHE_ENABLED', 'true') === 'true';
        
        if (self::$enabled && !is_dir(self::$cacheDir)) {
            mkdir(self::$cacheDir, 0755, true);
            file_put_contents(self::$cacheDir . '/index.html', '');
        }
    }
    
    public static function get($key, $default = null) {
        if (!self::$enabled) return $default;
        
        $file = self::$cacheDir . '/' . md5($key) . '.cache';
        
        if (!file_exists($file)) {
            return $default;
        }
        
        $data = unserialize(file_get_contents($file));
        
        if ($data['expire'] > 0 && $data['expire'] < time()) {
            unlink($file);
            return $default;
        }
        
        return $data['value'];
    }
    
    public static function set($key, $value, $ttl = null) {
        if (!self::$enabled) return false;
        
        $ttl = $ttl ?? (int)Env::get('CACHE_LIFETIME', 3600);
        $file = self::$cacheDir . '/' . md5($key) . '.cache';
        $data = [
            'value' => $value,
            'expire' => $ttl > 0 ? time() + $ttl : 0,
            'created' => time()
        ];
        
        return file_put_contents($file, serialize($data), LOCK_EX) !== false;
    }
    
    public static function remember($key, $callback, $ttl = null) {
        $value = self::get($key);
        
        if ($value === null) {
            $value = call_user_func($callback);
            self::set($key, $value, $ttl);
        }
        
        return $value;
    }
    
    public static function forget($key) {
        if (!self::$enabled) return true;
        
        $file = self::$cacheDir . '/' . md5($key) . '.cache';
        if (file_exists($file)) {
            return unlink($file);
        }
        return true;
    }
    
    public static function flush() {
        if (!self::$enabled) return true;
        
        $files = glob(self::$cacheDir . '/*.cache');
        foreach ($files as $file) {
            unlink($file);
        }
        return true;
    }
    
    public static function disable() {
        self::$enabled = false;
    }
    
    public static function enable() {
        self::$enabled = true;
    }
}

/**
 * Session Manager
 */
class Session {
    private static $started = false;
    private static $flashKey = '_ESSANCE_flash';
    
    public static function start($options = []) {
        if (!self::$started && session_status() === PHP_SESSION_NONE) {
            $defaultOptions = [
                'cookie_httponly' => true,
                'cookie_samesite' => 'Lax',
                'use_strict_mode' => true
            ];
            
            session_start(array_merge($defaultOptions, $options));
            self::$started = true;
            
            // Process flash messages
            self::processFlash();
        }
    }
    
    public static function get($key, $default = null) {
        self::start();
        return $_SESSION[$key] ?? $default;
    }
    
    public static function set($key, $value) {
        self::start();
        $_SESSION[$key] = $value;
    }
    
    public static function push($key, $value) {
        self::start();
        if (!isset($_SESSION[$key]) || !is_array($_SESSION[$key])) {
            $_SESSION[$key] = [];
        }
        $_SESSION[$key][] = $value;
    }
    
    public static function has($key) {
        self::start();
        return isset($_SESSION[$key]);
    }
    
    public static function forget($key) {
        self::start();
        unset($_SESSION[$key]);
    }
    
    public static function flush() {
        self::start();
        session_destroy();
        self::$started = false;
    }
    
    public static function regenerate() {
        self::start();
        session_regenerate_id(true);
    }
    
    public static function flash($key, $value) {
        self::start();
        if (!isset($_SESSION[self::$flashKey])) {
            $_SESSION[self::$flashKey] = [];
        }
        $_SESSION[self::$flashKey][$key] = $value;
    }
    
    public static function getFlash($key, $default = null) {
        self::start();
        return $_SESSION[self::$flashKey . '_old'][$key] ?? $default;
    }
    
    private static function processFlash() {
        if (isset($_SESSION[self::$flashKey . '_old'])) {
            unset($_SESSION[self::$flashKey . '_old']);
        }
        
        if (isset($_SESSION[self::$flashKey])) {
            $_SESSION[self::$flashKey . '_old'] = $_SESSION[self::$flashKey];
            unset($_SESSION[self::$flashKey]);
        }
    }
}

/**
 * Essance Framework Main Class
 */
class Essance {
    private static $instance = null;
    private $startTime;
    private $config = [];
    
    private function __construct() {
        $this->startTime = microtime(true);
        $this->init();
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function init() {
        // Load environment
        Env::load();
        
        // Set timezone
        date_default_timezone_set(Env::get('APP_TIMEZONE', 'UTC'));
        
        // Set error reporting
        if (Env::get('APP_DEBUG', 'false') === 'true') {
            error_reporting(E_ALL);
            ini_set('display_errors', 1);
        } else {
            error_reporting(E_ALL);
            ini_set('display_errors', 1);
        }
        
        // Initialize cache
        Cache::init();
        
        // Create .htaccess if not exists
        $this->createHtaccess();
        
        // Register error handler
        $this->registerErrorHandler();
        
        // Register autoloader
        spl_autoload_register(function ($class) {
            $file = str_replace('\\', '/', $class) . '.php';
            if (file_exists($file)) {
                require_once $file;
            }
        });
    }
    
    private function createHtaccess() {
        $htaccessFile = dirname($_SERVER['SCRIPT_FILENAME']) . '/.htaccess';
        
        if (!file_exists($htaccessFile)) {
            $content = "# Essance Framework Auto-Generated .htaccess\n";
            $content .= "# Version: " . ESSANCE_VERSION . "\n";
            $content .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";
            
            $content .= "# Enable Rewrite Engine\n";
            $content .= "RewriteEngine On\n\n";
            
            $content .= "# Redirect to HTTPS (uncomment if needed)\n";
            $content .= "# RewriteCond %{HTTPS} off\n";
            $content .= "# RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n";
            
            $content .= "# Remove trailing slash\n";
            $content .= "RewriteCond %{REQUEST_FILENAME} !-d\n";
            $content .= "RewriteCond %{REQUEST_URI} (.+)/$\n";
            $content .= "RewriteRule ^ %1 [L,R=301]\n\n";
            
            $content .= "# Route all requests to index.php\n";
            $content .= "RewriteCond %{REQUEST_FILENAME} !-f\n";
            $content .= "RewriteCond %{REQUEST_FILENAME} !-d\n";
            $content .= "RewriteRule ^(.*)$ index.php [QSA,L]\n\n";
            
            $content .= "# Security Headers\n";
            $content .= "<IfModule mod_headers.c>\n";
            $content .= "    Header set X-Frame-Options \"SAMEORIGIN\"\n";
            $content .= "    Header set X-Content-Type-Options \"nosniff\"\n";
            $content .= "    Header set X-XSS-Protection \"1; mode=block\"\n";
            $content .= "    Header set Referrer-Policy \"strict-origin-when-cross-origin\"\n";
            $content .= "</IfModule>\n\n";
            
            $content .= "# Prevent access to sensitive files\n";
            $content .= "<FilesMatch \"^\\.(env|git|htaccess)\">\n";
            $content .= "    Order allow,deny\n";
            $content .= "    Deny from all\n";
            $content .= "</FilesMatch>\n\n";
            
            $content .= "# Compression\n";
            $content .= "<IfModule mod_deflate.c>\n";
            $content .= "    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css\n";
            $content .= "    AddOutputFilterByType DEFLATE text/javascript application/javascript application/x-javascript\n";
            $content .= "    AddOutputFilterByType DEFLATE application/json application/xml application/rss+xml\n";
            $content .= "    AddOutputFilterByType DEFLATE font/truetype font/opentype image/svg+xml\n";
            $content .= "</IfModule>\n\n";
            
            $content .= "# Browser Caching\n";
            $content .= "<IfModule mod_expires.c>\n";
            $content .= "    ExpiresActive On\n";
            $content .= "    ExpiresByType image/jpg \"access plus 1 year\"\n";
            $content .= "    ExpiresByType image/jpeg \"access plus 1 year\"\n";
            $content .= "    ExpiresByType image/gif \"access plus 1 year\"\n";
            $content .= "    ExpiresByType image/png \"access plus 1 year\"\n";
            $content .= "    ExpiresByType image/webp \"access plus 1 year\"\n";
            $content .= "    ExpiresByType text/css \"access plus 1 month\"\n";
            $content .= "    ExpiresByType text/javascript \"access plus 1 month\"\n";
            $content .= "    ExpiresByType application/javascript \"access plus 1 month\"\n";
            $content .= "    ExpiresByType application/pdf \"access plus 1 month\"\n";
            $content .= "    ExpiresByType font/woff2 \"access plus 1 year\"\n";
            $content .= "</IfModule>\n\n";
            
            $content .= "# Disable directory browsing\n";
            $content .= "Options -Indexes\n\n";
            
            $content .= "# UTF-8 encoding\n";
            $content .= "AddDefaultCharset UTF-8\n";
            
            file_put_contents($htaccessFile, $content);
        }
    }
    
    private function registerErrorHandler() {
        if (Env::get('APP_DEBUG', 'false') === 'true') {
            set_error_handler(function($severity, $message, $file, $line) {
                throw new \ErrorException($message, 0, $severity, $file, $line);
            });
            
            set_exception_handler(function($exception) {
                http_response_code(500);
                echo '<div style="font-family: monospace; padding: 20px; background: #f5f5f5;">';
                echo '<h2 style="color: #e74c3c;">Exception: ' . get_class($exception) . '</h2>';
                echo '<p><strong>Message:</strong> ' . htmlspecialchars($exception->getMessage()) . '</p>';
                echo '<p><strong>File:</strong> ' . $exception->getFile() . ':' . $exception->getLine() . '</p>';
                echo '<h3>Stack Trace:</h3>';
                echo '<pre>' . htmlspecialchars($exception->getTraceAsString()) . '</pre>';
                echo '<pre>Powered by Essance Framework</pre> '. ESSANCE_VERSION .', Developed by Nader Mahbub Khan';
                echo '</div>';
            });
        }
    }
    
    public function run() {
        try {
            Router::dispatch();
        } catch (\Exception $e) {
            if (Env::get('APP_DEBUG', 'false') === 'true') {
                throw $e;
            }
            http_response_code(500);
            echo '<h1>500 - Internal Server Error</h1>';
        }
        
        if (Env::get('APP_DEBUG', 'false') === 'true') {
            $this->showDebugBar();
        }
    }
    
    private function showDebugBar() {
        $time = round((microtime(true) - $this->startTime) * 1000, 2);
        $memory = round(memory_get_peak_usage() / 1024 / 1024, 2);
        $files = count(get_included_files());
        
        echo "\n<!-- Essance Framework Debug Info -->\n";
        echo "<!-- Version: " . ESSANCE_VERSION . " -->\n";
        echo "<!-- Execution Time: {$time}ms -->\n";
        echo "<!-- Memory Usage: {$memory}MB -->\n";
        echo "<!-- Files Included: {$files} -->\n";
        echo "<!-- PHP Version: " . PHP_VERSION . " -->\n";
    }
    
    public static function version() {
        return ESSANCE_VERSION;
    }
}

// Helper Functions
function ESSANCE() {
    return Essance::getInstance();
}

function env($key, $default = null) {
    return Env::get($key, $default);
}

function route($name, $params = []) {
    return Router::url($name, $params);
}

function cache($key, $value = null, $ttl = null) {
    if ($value === null) {
        return Cache::get($key);
    }
    return Cache::set($key, $value, $ttl);
}

function session($key, $value = null) {
    if ($value === null) {
        return Session::get($key);
    }
    Session::set($key, $value);
}

function flash($key, $value = null) {
    if ($value === null) {
        return Session::getFlash($key);
    }
    Session::flash($key, $value);
}

function response() {
    return new Essance\Response();
}

function request() {
    return new Request();
}

function redirect($url, $status = 302) {
    Response::redirect($url, $status);
}

function view($file, $data = []) {
    Response::view($file, $data);
}

// Initialize Essance Framework
ESSANCE();
