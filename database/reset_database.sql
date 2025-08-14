-- Script de reset de base de datos para práctica
-- Aplicación TodoList Vulnerable - Propósito Educativo
-- Este script permite resetear la base de datos a un estado limpio para nuevas sesiones de práctica

-- ============================================================================
-- ADVERTENCIA Y CONFIRMACIÓN
-- ============================================================================

-- ADVERTENCIA: Este script eliminará TODOS los datos de la base de datos
-- Solo ejecutar si estás seguro de que quieres resetear completamente la base de datos

SELECT 'ADVERTENCIA: Este script eliminará TODOS los datos existentes' as warning;
SELECT 'Presiona Ctrl+C para cancelar si no quieres continuar' as warning;

-- Pausa para dar tiempo al usuario de cancelar
SELECT pg_sleep(3);

-- ============================================================================
-- BACKUP DE DATOS EXISTENTES (OPCIONAL)
-- ============================================================================

-- Crear tabla temporal para backup de usuarios (opcional)
-- Descomenta las siguientes líneas si quieres hacer backup antes del reset

/*
DROP TABLE IF EXISTS users_backup;
CREATE TABLE users_backup AS SELECT * FROM users;

DROP TABLE IF EXISTS tasks_backup;  
CREATE TABLE tasks_backup AS SELECT * FROM tasks;

SELECT 'Backup creado en users_backup y tasks_backup' as info;
*/

-- ============================================================================
-- ELIMINACIÓN DE DATOS EXISTENTES
-- ============================================================================

-- Eliminar todas las tareas (respeta foreign keys)
DELETE FROM tasks;
SELECT 'Todas las tareas han sido eliminadas' as info;

-- Eliminar todos los usuarios
DELETE FROM users;
SELECT 'Todos los usuarios han sido eliminados' as info;

-- Resetear secuencias para que los IDs empiecen desde 1
ALTER SEQUENCE users_id_seq RESTART WITH 1;
ALTER SEQUENCE tasks_id_seq RESTART WITH 1;
SELECT 'Secuencias de IDs reseteadas' as info;

-- ============================================================================
-- VERIFICACIÓN DE LIMPIEZA
-- ============================================================================

-- Verificar que las tablas estén vacías
SELECT 'Verificando limpieza de datos:' as info;
SELECT 'Usuarios restantes: ' || COUNT(*) as verificacion FROM users;
SELECT 'Tareas restantes: ' || COUNT(*) as verificacion FROM tasks;

-- ============================================================================
-- RECREACIÓN DE ESTRUCTURA (SI ES NECESARIO)
-- ============================================================================

-- Verificar que las tablas existan y tengan la estructura correcta
SELECT 'Verificando estructura de tablas:' as info;

-- Verificar tabla users
SELECT 'Tabla users - Columnas:' as info;
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'users' 
ORDER BY ordinal_position;

-- Verificar tabla tasks
SELECT 'Tabla tasks - Columnas:' as info;
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'tasks' 
ORDER BY ordinal_position;

-- Verificar índices
SELECT 'Índices existentes:' as info;
SELECT indexname, tablename 
FROM pg_indexes 
WHERE tablename IN ('users', 'tasks')
ORDER BY tablename, indexname;

-- ============================================================================
-- INSERCIÓN DE DATOS BÁSICOS PARA TESTING
-- ============================================================================

-- Insertar usuario administrador básico
INSERT INTO users (username, password, email) VALUES 
('admin', 'admin123', 'admin@todolist.com');

-- Insertar usuario de prueba básico
INSERT INTO users (username, password, email) VALUES 
('testuser', 'password123', 'test@example.com');

SELECT 'Usuarios básicos creados para testing inicial' as info;

-- Insertar algunas tareas básicas
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(1, 'Configurar aplicación', 'Verificar que la aplicación funcione correctamente', false),
(1, 'Revisar vulnerabilidades', 'Comprobar que las vulnerabilidades estén implementadas', false),
(2, 'Primera tarea de prueba', 'Tarea de ejemplo para el usuario de prueba', false);

SELECT 'Tareas básicas creadas para testing inicial' as info;

-- ============================================================================
-- INSTRUCCIONES POST-RESET
-- ============================================================================

SELECT '============================================================================' as separator;
SELECT 'RESET COMPLETADO EXITOSAMENTE' as status;
SELECT '============================================================================' as separator;

SELECT 'La base de datos ha sido reseteada completamente.' as info;
SELECT 'Usuarios disponibles para testing inicial:' as info;
SELECT '- admin / admin123 (usuario administrador)' as info;
SELECT '- testuser / password123 (usuario de prueba)' as info;
SELECT '' as info;
SELECT 'Para cargar datos de ejemplo completos, ejecuta:' as info;
SELECT '- sample_data.sql (datos básicos de ejemplo)' as info;
SELECT '- vulnerability_test_data.sql (datos específicos para testing)' as info;
SELECT '' as info;
SELECT 'Para verificar el estado actual:' as info;
SELECT '- SELECT COUNT(*) FROM users; (debería mostrar 2)' as info;
SELECT '- SELECT COUNT(*) FROM tasks; (debería mostrar 3)' as info;

-- ============================================================================
-- VERIFICACIÓN FINAL
-- ============================================================================

-- Mostrar estado final
SELECT 'ESTADO FINAL DE LA BASE DE DATOS:' as info;
SELECT 'Total usuarios: ' || COUNT(*) as estado FROM users;
SELECT 'Total tareas: ' || COUNT(*) as estado FROM tasks;

-- Mostrar usuarios creados
SELECT 'USUARIOS DISPONIBLES:' as info;
SELECT id, username, email, created_at FROM users ORDER BY id;

-- Mostrar tareas creadas
SELECT 'TAREAS DISPONIBLES:' as info;
SELECT t.id, u.username as propietario, t.title, t.completed 
FROM tasks t 
JOIN users u ON t.user_id = u.id 
ORDER BY t.id;