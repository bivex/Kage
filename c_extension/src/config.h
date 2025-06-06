/**
 * Copyright (c) 2025 [Your Name], Individual Entrepreneur
 * INN: [Your Tax ID Number]
 * Created: 2025-06-06 21:46
 * Last Updated: 2025-06-07 02:32
 * All rights reserved. Unauthorized copying, modification,
 * distribution, or use is strictly prohibited.
 */

#ifndef PHP_KAGE_H
#define PHP_KAGE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_extensions.h"
#include <sodium.h>
#include <stdint.h>

// Define the name of our extension
#define PHP_KAGE_EXTNAME "kage"
#define PHP_KAGE_VERSION "0.1.0"

// Declare the functions that will be exposed to PHP userland
PHP_FUNCTION(kage_encrypt_c);
PHP_FUNCTION(kage_decrypt_c);

// Module globals structure
ZEND_BEGIN_MODULE_GLOBALS(kage)
    zend_bool debug;
ZEND_END_MODULE_GLOBALS(kage)

// Declare the globals as extern
extern ZEND_DECLARE_MODULE_GLOBALS(kage);

// Define the accessor macro
#define KAGE_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(kage, v)

// Module lifecycle functions
PHP_GINIT_FUNCTION(kage);
PHP_MINIT_FUNCTION(kage);
PHP_MSHUTDOWN_FUNCTION(kage);
PHP_RINIT_FUNCTION(kage);
PHP_RSHUTDOWN_FUNCTION(kage);
PHP_MINFO_FUNCTION(kage);

// Module entry point
extern zend_module_entry kage_module_entry;
#define phpext_kage_ptr &kage_module_entry

#endif /* PHP_KAGE_H */ 