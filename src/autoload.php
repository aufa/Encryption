<?php
/**
 * PSR Autoloader
 */
return spl_autoload_register(function($className) {
    /**
     * Determine Base Directory
     */
    $baseDir = function_exists('realpath') ? realpath(__DIR__) : __DIR__;
    $baseDir = $baseDir ? $baseDir : __DIR__;
    $baseDir = $baseDir.'/Encryption/';

    // project-specific namespace prefix
    $prefix  = 'Aufa\\Encryption\\';
    // does the class use the namespace prefix?
    $len = strlen($prefix);
    $className = ltrim($className, '\\');
    if (strncmp($prefix, $className, $len) !== 0) {
        // no, move to the next registered autoloader
        return;
    }

    $className = substr($className, $len);

    $nameSpace = '';
    if ($lastNsPos = strripos($className, '\\')) {
        $namespace = str_replace('\\', '/', $className);
        $namespace = substr($namespace, 0, $lastNsPos);
        $className = substr($className, $lastNsPos + 1);
        if (is_dir($baseDir. $namespace . '/')) {
            $baseDir .= $namespace . '/';
        } else {
            if (is_dir($baseDir . strtoupper($namespace.'/'))) {
                $baseDir .= strtoupper($namespace) . '/';
            } elseif (is_dir($baseDir . ucwords($namespace.'/'))) {
                $baseDir .= ucwords($namespace) . '/';
            }
        }
    }

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
