-- Script para poblar base de datos con datos de ejemplo
-- Aplicación TodoList Vulnerable - Propósito Educativo
-- Este script crea usuarios y tareas de ejemplo para testing de vulnerabilidades

-- Limpiar datos existentes (opcional)
-- TRUNCATE TABLE tasks CASCADE;
-- TRUNCATE TABLE users CASCADE;

-- ============================================================================
-- USUARIOS DE EJEMPLO CON DIFERENTES NIVELES DE ACCESO
-- ============================================================================

-- Usuario administrador (para testing de escalación de privilegios)
INSERT INTO users (username, password, email) VALUES 
('admin', 'admin123', 'admin@todolist.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario regular básico
INSERT INTO users (username, password, email) VALUES 
('usuario1', 'password123', 'usuario1@example.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario con contraseña débil (para testing de fuerza bruta)
INSERT INTO users (username, password, email) VALUES 
('testuser', '123', 'test@example.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario con datos especiales para testing de inyección
INSERT INTO users (username, password, email) VALUES 
('sqltest', 'pass''word', 'sql@test.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario con caracteres especiales para testing XSS
INSERT INTO users (username, password, email) VALUES 
('xssuser', 'password', 'xss@test.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario para testing de IDOR
INSERT INTO users (username, password, email) VALUES 
('victim', 'victim123', 'victim@example.com')
ON CONFLICT (username) DO NOTHING;

-- Usuario atacante para testing de IDOR
INSERT INTO users (username, password, email) VALUES 
('attacker', 'attacker123', 'attacker@example.com')
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- TAREAS DE EJEMPLO PARA TESTING DE VULNERABILIDADES
-- ============================================================================

-- Tareas normales para el usuario admin (ID: 1)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(1, 'Revisar logs del sistema', 'Verificar que no haya actividad sospechosa en los logs', false),
(1, 'Actualizar documentación', 'Mantener la documentación del proyecto actualizada', true),
(1, 'Configurar backup automático', 'Implementar sistema de respaldo automático de la base de datos', false);

-- Tareas normales para usuario1 (ID: 2)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(2, 'Completar proyecto final', 'Terminar el desarrollo del proyecto de fin de curso', false),
(2, 'Estudiar para examen', 'Repasar conceptos de ciberseguridad para el examen', false),
(2, 'Comprar víveres', 'Lista de compras para la semana', true);

-- Tareas con payloads XSS para testing (usuario xssuser - ID: 5)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(5, '<script>alert("XSS en título")</script>', 'Tarea normal con XSS en el título', false),
(5, 'Tarea con XSS en descripción', '<img src=x onerror=alert("XSS en descripción")>', false),
(5, 'XSS con evento onclick', '<div onclick=alert("XSS onclick")>Click me</div>', false),
(5, 'XSS con iframe', '<iframe src="javascript:alert(''XSS iframe'')"></iframe>', false);

-- Tareas con payloads de inyección SQL para testing (usuario sqltest - ID: 4)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(4, 'Tarea normal', 'Descripción normal para testing', false),
(4, 'Test SQL Injection', ''' OR 1=1 --', false),
(4, 'Union SQL Injection', ''' UNION SELECT username, password FROM users --', false),
(4, 'Drop Table Test', '''; DROP TABLE tasks; --', false);

-- Tareas para testing de IDOR (usuario victim - ID: 6)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(6, 'Información confidencial', 'Esta tarea contiene información sensible que solo debería ver el propietario', false),
(6, 'Datos personales', 'Número de tarjeta: 1234-5678-9012-3456 (FAKE)', false),
(6, 'Contraseña de backup', 'Password del sistema de backup: backup123 (FAKE)', true);

-- Tareas para el atacante (usuario attacker - ID: 7)
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(7, 'Plan de ataque IDOR', 'Intentar acceder a tareas de otros usuarios modificando IDs', false),
(7, 'Testing de vulnerabilidades', 'Probar diferentes vectores de ataque en la aplicación', false);

-- ============================================================================
-- DATOS ADICIONALES PARA TESTING AVANZADO
-- ============================================================================

-- Tareas con diferentes estados para testing de lógica de negocio
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(2, 'Tarea completada hace tiempo', 'Esta tarea fue marcada como completada', true),
(2, 'Tarea pendiente urgente', 'Esta tarea tiene alta prioridad', false),
(2, 'Tarea con descripción muy larga', 'Esta es una descripción extremadamente larga que podría causar problemas de renderizado o truncamiento en la interfaz de usuario. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.', false);

-- Tareas con caracteres especiales para testing de encoding
INSERT INTO tasks (user_id, title, description, completed) VALUES 
(3, 'Tarea con acentos', 'Descripción con caracteres especiales: ñáéíóú', false),
(3, 'Emojis y símbolos', 'Testing con emojis 🔒🛡️💻 y símbolos especiales @#$%^&*()', false),
(3, 'Caracteres Unicode', 'Testing con caracteres Unicode: 中文, العربية, русский', false);

-- ============================================================================
-- VERIFICACIÓN DE DATOS INSERTADOS
-- ============================================================================

-- Mostrar resumen de usuarios creados
SELECT 'USUARIOS CREADOS:' as info;
SELECT id, username, email, created_at FROM users ORDER BY id;

-- Mostrar resumen de tareas creadas
SELECT 'TAREAS CREADAS:' as info;
SELECT COUNT(*) as total_tareas FROM tasks;
SELECT user_id, COUNT(*) as tareas_por_usuario FROM tasks GROUP BY user_id ORDER BY user_id;

-- Mostrar algunas tareas de ejemplo
SELECT 'EJEMPLOS DE TAREAS:' as info;
SELECT t.id, u.username, t.title, LEFT(t.description, 50) as descripcion_corta, t.completed 
FROM tasks t 
JOIN users u ON t.user_id = u.id 
ORDER BY t.id 
LIMIT 10;