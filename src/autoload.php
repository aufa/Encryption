<?php
/**
 * PSR Autoloader
 */
return spl_autoload_register(function($className) {
    /**
     * Determine Base Directory
     */
    $baseDir = __DIR__ . '/Encryption/';
    // project-specific namespace prefix
    $prefix  = 'Aufa\\Encryption\\';
    $className = ltrim($className, '\\');
    if (stripos($className, $prefix) !== 0) {
        // no, move to the next registered auto loader
        return;
    }
    $className = substr($className, strlen($prefix));
    $className = str_replace('\\', '//', $className);

    /**
     * Fix File for
     */
    if (file_exists($baseDir . $className . '.php')) {
        require_once ($baseDir . $className . '.php');
    } elseif (file_exists($baseDir . ucwords($className) . '.php')) {
        require_once ($baseDir . ucwords($className) . '.php');
    } elseif (file_exists($baseDir . strtolower($className) . '.php')) {
        require_once ($baseDir . strtolower($className) . '.php');
    }
});
