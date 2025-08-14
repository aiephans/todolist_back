# Scripts de Base de Datos - TodoList Vulnerable

Este directorio contiene todos los scripts SQL necesarios para configurar, poblar y testear la base de datos de la aplicación TodoList vulnerable con fines educativos.

## Archivos Disponibles

### 1. `init.sql`
Script de inicialización que crea la estructura básica de la base de datos.
- Crea las tablas `users` y `tasks`
- Define las relaciones y constraints
- Crea índices para mejor rendimiento

### 2. `sample_data.sql`
Script para poblar la base de datos con datos de ejemplo para testing general.
- **Usuarios de ejemplo**: 7 usuarios con diferentes perfiles
- **Tareas normales**: Tareas típicas para testing de funcionalidad
- **Datos variados**: Diferentes tipos de contenido para testing

#### Usuarios incluidos:
- `admin` / `admin123` - Usuario administrador
- `usuario1` / `password123` - Usuario regular
- `testuser` / `123` - Usuario con contraseña débil
- `sqltest` / `pass'word` - Usuario con caracteres especiales
- `xssuser` / `password` - Usuario para testing XSS
- `victim` / `victim123` - Usuario víctima para IDOR
- `attacker` / `attacker123` - Usuario atacante para IDOR

### 3. `vulnerability_test_data.sql`
Script especializado que crea datos específicos para testing de cada vulnerabilidad.

#### Datos por tipo de vulnerabilidad:

**SQL Injection:**
- Usuario: `sqli_tester` / `password`
- Tareas con payloads: `' OR '1'='1`, `UNION SELECT`, etc.

**XSS (Cross-Site Scripting):**
- Usuario: `xss_tester` / `password`
- Tareas con payloads: `<script>alert("XSS")</script>`, eventos onclick, etc.

**IDOR (Insecure Direct Object Reference):**
- Usuarios: `idor_victim1`, `idor_victim2`, `idor_attacker`
- Tareas sensibles para testing de acceso no autorizado

**Autenticación Débil:**
- Usuarios con contraseñas comunes: `123`, `password`, `admin`, etc.

**Validación de Entrada:**
- Usuario: `validation_tester`
- Datos extremos: strings largos, caracteres especiales, valores vacíos

**CSRF (Cross-Site Request Forgery):**
- Usuario: `csrf_victim`
- Tareas críticas para testing de modificación no autorizada

### 4. `reset_database.sql`
Script para resetear completamente la base de datos a un estado limpio.
- Elimina todos los datos existentes
- Resetea las secuencias de IDs
- Crea usuarios básicos para testing inicial
- Incluye verificaciones de seguridad

### 5. `testing_scripts.sql`
Script de verificación que contiene queries para testear que las vulnerabilidades estén correctamente implementadas.
- Tests automatizados para cada vulnerabilidad
- Verificación de datos de testing
- Queries de ejemplo para testing manual
- Resumen de estado de la base de datos

## Instrucciones de Uso

### Configuración Inicial

1. **Crear la estructura básica:**
```sql
\i backend/database/init.sql
```

2. **Poblar con datos de ejemplo:**
```sql
\i backend/database/sample_data.sql
```

3. **Agregar datos específicos para vulnerabilidades:**
```sql
\i backend/database/vulnerability_test_data.sql
```

### Testing y Verificación

4. **Ejecutar tests de verificación:**
```sql
\i backend/database/testing_scripts.sql
```

### Reset para Nueva Sesión

5. **Resetear base de datos:**
```sql
\i backend/database/reset_database.sql
```

## Uso con psql

```bash
# Conectar a la base de datos
psql $DATABASE_URL

# Ejecutar script específico
\i backend/database/sample_data.sql

# Ver tablas
\dt

# Ver usuarios
SELECT * FROM users;

# Ver tareas
SELECT * FROM tasks;
```

## Uso con aplicación Python

```python
# Desde el directorio backend
python -c "from database.init_db import *; init_database(); create_sample_users(); create_sample_tasks()"
```

## Consideraciones de Seguridad

⚠️ **IMPORTANTE**: Estos scripts están diseñados específicamente para fines educativos y contienen vulnerabilidades intencionalmente implementadas.

- **NO usar en producción**
- **NO usar con datos reales**
- Las contraseñas están almacenadas en texto plano intencionalmente
- Los datos incluyen payloads maliciosos para testing
- Algunos scripts pueden ser destructivos (reset_database.sql)

## Estructura de Datos

### Tabla Users
```sql
id SERIAL PRIMARY KEY
username VARCHAR(50) UNIQUE NOT NULL
password VARCHAR(255) NOT NULL  -- Texto plano (vulnerable)
email VARCHAR(100)
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
```

### Tabla Tasks
```sql
id SERIAL PRIMARY KEY
title VARCHAR(200) NOT NULL
description TEXT
completed BOOLEAN DEFAULT FALSE
user_id INTEGER REFERENCES users(id)
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
```

## Vulnerabilidades Implementadas

1. **SQL Injection** - Queries sin parametrización
2. **XSS** - Contenido sin sanitización
3. **IDOR** - Referencias directas a objetos sin validación
4. **Autenticación Débil** - Contraseñas en texto plano
5. **Validación Insuficiente** - Datos extremos sin validación
6. **CSRF** - Sin tokens de protección

## Soporte

Para más información sobre el uso de estos scripts o la aplicación en general, consulta:
- Documentación de requisitos: `.kiro/specs/vulnerable-todolist-app/requirements.md`
- Documentación de diseño: `.kiro/specs/vulnerable-todolist-app/design.md`
- Lista de tareas: `.kiro/specs/vulnerable-todolist-app/tasks.md`