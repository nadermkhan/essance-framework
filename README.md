# Essance Framework

A lightweight, single-file PHP framework designed to modernize legacy projects with zero dependencies.

## Installation

Install via Composer:

```bash
composer require nader/essance
```

## Features

- ✨ **Single-file architecture** - Just one file to include
- 🚀 **Modern routing system** with RESTful support
- 📁 **Chunked file uploads** with validation
- 💾 **Built-in caching system**
- 🔐 **Session management** with flash messages
- ⚙️ **Environment configuration** (.env support)
- 🛡️ **Security features** built-in
- 📦 **Zero dependencies**

## Quick Start

```php
<?php
require_once 'vendor/autoload.php';

use Essance\Router;
use Essance\Response;

// Define a route
Router::get('/', function() {
    return Response::json(['message' => 'Hello from Essance!']);
});

// Define a route with parameters
Router::get('/user/{id}', function($request) {
    $userId = $request->param('id');
    return Response::json(['user_id' => $userId]);
});

// Run the application
Essance\Essance::getInstance()->run();
```

## Basic Usage

### Routing
```php
// GET request
Router::get('/path', function($request) {
    // Handle request
});

// POST request
Router::post('/api/users', function($request) {
    $name = $request->input('name');
    return Response::json(['created' => true]);
});

// Route with parameters
Router::get('/post/{id}', function($request) {
    $id = $request->param('id');
    return Response::json(['post_id' => $id]);
});

// Route groups
Router::group('/api', function() {
    Router::get('/users', 'UserController@index');
    Router::post('/users', 'UserController@store');
});
```

### File Uploads
```php
use Essance\ChunkUpload;

Router::post('/upload', function($request) {
    $uploader = new ChunkUpload('uploads');
    $result = $uploader->handleSimple($_FILES['file']);
    return Response::json($result);
});
```

### Caching
```php
use Essance\Cache;

// Set cache
Cache::set('key', 'value', 3600);

// Get cache
$value = Cache::get('key');

// Remember pattern
$users = Cache::remember('users', function() {
    // Expensive operation
    return ['user1', 'user2'];
}, 3600);
```

### Sessions
```php
use Essance\Session;

// Set session
Session::set('user_id', 123);

// Get session
$userId = Session::get('user_id');

// Flash messages
Session::flash('success', 'Operation completed!');
```

## Environment Configuration

Create a `.env` file in your project root:

```env
APP_NAME=MyApp
APP_ENV=production
APP_DEBUG=false
APP_URL=http://localhost

UPLOAD_MAX_SIZE=10485760
CACHE_ENABLED=true
CACHE_LIFETIME=3600
```

Access environment variables:
```php
$appName = env('APP_NAME', 'DefaultName');
```

## Requirements

- PHP 8.2 or higher
- Apache/Nginx with mod_rewrite

## License

Copyright (c) 2025 Nader Mahbub Khan

All rights reserved.

Unauthorized copying, modification, distribution, or use of this software,
via any medium, is strictly prohibited without the express written permission
of the author.

Branding, names, and visual elements associated with this software
may not be changed, removed, or reused under any circumstances.


## Author

Created by Nader Mahbub Khan

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/nadermkhan/essance-framework/issues).
