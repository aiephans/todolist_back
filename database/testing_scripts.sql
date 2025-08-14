-- Scripts de testing para verificar vulnerabilidades
-- Aplicación TodoList Vulnerable - Propósito Educativo
-- Este archivo contiene queries de testing para verificar que las vulnerabilidades funcionen correctamente

-- ============================================================================
-- TESTING DE INYECCIÓN SQL
-- ============================================================================

SELECT '=== TESTING DE INYECCIÓN SQL ===' as test_category;

-- Test 1: Verificar que existe el usuario para SQL injection
SELECT 'Test 1: Usuario sqli_tester existe' as test_name;
SELECT CASE 
    WHEN EXISTS(SELECT 1 FROM users WHERE username = 'sqli_tester') 
    THEN 'PASS: Usuario sqli_tester encontrado'
    ELSE 'FAIL: Usuario sqli_tester no encontrado'
END as result;

-- Test 2: Verificar tareas con payloads SQL injection
SELECT 'Test 2: Tareas con payloads SQL injection' as test_name;
SELECT COUNT(*) as payloads_count 
FROM tasks t 
JOIN users u ON t.user_id = u.id 
WHERE u.username = 'sqli_tester' 
AND (t.title LIKE '%OR%' OR t.title LIKE '%UNION%' OR t.description LIKE '%--');

-- Test 3: Simular query vulnerable (para documentación)
SELECT 'Test 3: Ejemplo de query vulnerable' as test_name;
SELECT 'Query vulnerable ejemplo:' as info;
SELECT 'SELECT * FROM tasks WHERE user_id = 1 AND title LIKE ''%'' OR ''1''=''1%''' as vulnerable_query;

-- ============================================================================
-- TESTING DE XSS (Cross-Site Scripting)
-- ============================================================================

SELECT '=== TESTING DE XSS ===' as test_category;

-- Test 4: Verificar usuario XSS tester
SELECT 'Test 4: Usuario xss_tester existe' as test_name;
SELECT CASE 
    WHEN EXISTS(SELECT 1 FROM users WHERE username = 'xss_tester') 
    THEN 'PASS: Usuario xss_tester encontrado'
    ELSE 'FAIL: Usuario xss_tester no encontrado'
END as result;

-- Test 5: Contar tareas con payloads XSS
SELECT 'Test 5: Tareas con payloads XSS' as test_name;
SELECT COUNT(*) as xss_payloads_count 
FROM tasks t 
JOIN users u ON t.user_id = u.id 
WHERE u.username = 'xss_tester' 
AND (t.title LIKE '%<script%' OR t.title LIKE '%onerror%' OR t.description LIKE '%<script%');

-- Test 6: Mostrar ejemplos de payloads XSS almacenados
SELECT 'Test 6: Ejemplos de payloads XSS' as test_name;
SELECT t.title, LEFT(t.description, 50) as description_preview
FROM tasks t 
JOIN users u ON t.user_id = u.id 
WHERE u.username = 'xss_tester' 
AND (t.title LIKE '%<%' OR t.description LIKE '%<%')
LIMIT 5;

-- ============================================================================
-- TESTING DE IDOR (Insecure Direct Object Reference)
-- ============================================================================

SELECT '=== TESTING DE IDOR ===' as test_category;

-- Test 7: Verificar usuarios IDOR
SELECT 'Test 7: Usuarios IDOR existen' as test_name;
SELECT username, id 
FROM users 
WHERE username IN ('idor_victim1', 'idor_victim2', 'idor_attacker')
ORDER BY username;

-- Test 8: Verificar tareas sensibles para IDOR testing
SELECT 'Test 8: Tareas sensibles para IDOR' as test_name;
SELECT u.username, COUNT(t.id) as sensitive_tasks
FROM users u
JOIN tasks t ON u.id = t.user_id
WHERE u.username LIKE 'idor_victim%'
GROUP BY u.username;

-- Test 9: Mostrar IDs de tareas para IDOR testing
SELECT 'Test 9: IDs de tareas para IDOR testing' as test_name;
SELECT t.id as task_id, u.username as owner, t.title
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username LIKE 'idor_%'
ORDER BY t.id;

-- ============================================================================
-- TESTING DE AUTENTICACIÓN DÉBIL
-- ============================================================================

SELECT '=== TESTING DE AUTENTICACIÓN DÉBIL ===' as test_category;

-- Test 10: Verificar usuarios con contraseñas débiles
SELECT 'Test 10: Usuarios con contraseñas débiles' as test_name;
SELECT username, password, 
    CASE 
        WHEN LENGTH(password) < 4 THEN 'MUY DÉBIL'
        WHEN password IN ('password', 'admin', 'qwerty', '12345') THEN 'COMÚN'
        ELSE 'DÉBIL'
    END as strength_level
FROM users 
WHERE username LIKE 'weak_%' OR username = 'common_user'
ORDER BY LENGTH(password);

-- Test 11: Verificar almacenamiento de contraseñas en texto plano
SELECT 'Test 11: Contraseñas en texto plano' as test_name;
SELECT 'VULNERABLE: Contraseñas almacenadas en texto plano' as vulnerability_status;
SELECT COUNT(*) as total_users_with_plain_passwords FROM users;

-- ============================================================================
-- TESTING DE VALIDACIÓN DE ENTRADA
-- ============================================================================

SELECT '=== TESTING DE VALIDACIÓN DE ENTRADA ===' as test_category;

-- Test 12: Verificar datos extremos para validación
SELECT 'Test 12: Datos extremos para testing' as test_name;
SELECT 
    COUNT(CASE WHEN LENGTH(title) > 100 THEN 1 END) as long_titles,
    COUNT(CASE WHEN LENGTH(description) > 500 THEN 1 END) as long_descriptions,
    COUNT(CASE WHEN title = '' OR title IS NULL THEN 1 END) as empty_titles
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username = 'validation_tester';

-- Test 13: Verificar caracteres especiales
SELECT 'Test 13: Caracteres especiales en datos' as test_name;
SELECT title, description
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username = 'validation_tester'
AND (title ~ '[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]' OR description ~ '[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]')
LIMIT 3;

-- ============================================================================
-- TESTING DE CSRF
-- ============================================================================

SELECT '=== TESTING DE CSRF ===' as test_category;

-- Test 14: Verificar usuario CSRF victim
SELECT 'Test 14: Usuario CSRF victim' as test_name;
SELECT CASE 
    WHEN EXISTS(SELECT 1 FROM users WHERE username = 'csrf_victim') 
    THEN 'PASS: Usuario csrf_victim encontrado'
    ELSE 'FAIL: Usuario csrf_victim no encontrado'
END as result;

-- Test 15: Tareas para CSRF testing
SELECT 'Test 15: Tareas para CSRF testing' as test_name;
SELECT t.id, t.title, t.completed
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username = 'csrf_victim';

-- ============================================================================
-- RESUMEN GENERAL DE TESTING
-- ============================================================================

SELECT '=== RESUMEN GENERAL ===' as test_category;

-- Test 16: Resumen de todos los datos de testing
SELECT 'Test 16: Resumen completo de datos de testing' as test_name;

SELECT 'USUARIOS DE TESTING:' as category;
SELECT 
    'SQL Injection: ' || COUNT(CASE WHEN username LIKE '%sqli%' THEN 1 END) ||
    ', XSS: ' || COUNT(CASE WHEN username LIKE '%xss%' THEN 1 END) ||
    ', IDOR: ' || COUNT(CASE WHEN username LIKE '%idor%' THEN 1 END) ||
    ', Weak Auth: ' || COUNT(CASE WHEN username LIKE '%weak%' OR username = 'common_user' THEN 1 END) ||
    ', Validation: ' || COUNT(CASE WHEN username LIKE '%validation%' THEN 1 END) ||
    ', CSRF: ' || COUNT(CASE WHEN username LIKE '%csrf%' THEN 1 END) as user_counts
FROM users;

SELECT 'TAREAS DE TESTING:' as category;
SELECT COUNT(*) as total_testing_tasks
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username LIKE '%test%' OR u.username LIKE '%sqli%' OR u.username LIKE '%xss%' 
   OR u.username LIKE '%idor%' OR u.username LIKE '%validation%' OR u.username LIKE '%csrf%';

-- ============================================================================
-- QUERIES PARA VERIFICAR VULNERABILIDADES EN VIVO
-- ============================================================================

SELECT '=== QUERIES DE VERIFICACIÓN EN VIVO ===' as test_category;

-- Query para verificar que SQL injection es posible
SELECT 'Query para testing SQL Injection en aplicación:' as info;
SELECT 'GET /tasks?search='' OR ''1''=''1' as test_endpoint;

-- Query para verificar XSS
SELECT 'Payload XSS para testing en aplicación:' as info;
SELECT '<script>alert("XSS Test")</script>' as xss_payload;

-- IDs para testing IDOR
SELECT 'IDs de tareas para testing IDOR:' as info;
SELECT DISTINCT t.id as task_ids_for_idor_testing
FROM tasks t
JOIN users u ON t.user_id = u.id
WHERE u.username LIKE 'idor_victim%'
ORDER BY t.id
LIMIT 5;

-- Credenciales para testing de autenticación débil
SELECT 'Credenciales para brute force testing:' as info;
SELECT username || ':' || password as credentials
FROM users 
WHERE username LIKE 'weak_%' OR username = 'common_user'
LIMIT 5;

SELECT '=== FIN DE TESTING SCRIPTS ===' as end_marker;