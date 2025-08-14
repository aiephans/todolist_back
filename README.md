# Backend - Vulnerable TodoList API

API REST desarrollada con FastAPI que contiene vulnerabilidades intencionalmente implementadas para propósitos educativos.

## Instalación

### Instalación Local

1. **Crear entorno virtual**:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

2. **Instalar dependencias**:
```bash
pip install -r requirements.txt
```

3. **Configurar variables de entorno**:
```bash
cp .env.example .env
# Editar .env con tus configuraciones
```

4. **Ejecutar la aplicación**:
```bash
uvicorn main:app --reload
```

La API estará disponible en `http://localhost:8000`

## Configuración

### Variables de Entorno

- `DATABASE_URL`: URL de conexión a PostgreSQL
- `SECRET_KEY`: Clave secreta para JWT (intencionalmente débil)
- `ALGORITHM`: Algoritmo para JWT
- `FRONTEND_URL`: URL del frontend para CORS

### Base de Datos

La aplicación requiere PostgreSQL. Configurar la URL de conexión en la variable `DATABASE_URL`.

## Endpoints de la API

### Autenticación
- `POST /auth/register` - Registro de usuario
- `POST /auth/login` - Inicio de sesión

### Tareas
- `GET /tasks` - Listar tareas del usuario
- `POST /tasks` - Crear nueva tarea
- `PUT /tasks/{task_id}` - Actualizar tarea
- `DELETE /tasks/{task_id}` - Eliminar tarea

## Documentación de la API

Una vez ejecutada la aplicación, la documentación interactiva estará disponible en:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Vulnerabilidades Implementadas

⚠️ **Las siguientes vulnerabilidades están implementadas intencionalmente**:

1. **Inyección SQL**: En endpoints de consulta
2. **Almacenamiento inseguro**: Contraseñas en texto plano
3. **JWT débil**: Sin expiración y clave secreta débil
4. **IDOR**: Acceso a recursos de otros usuarios
5. **Información sensible**: Errores verbosos con stack traces

## Despliegue en Render

1. Conectar repositorio a Render
2. Configurar como Web Service
3. Establecer variables de entorno
4. Configurar base de datos PostgreSQL
5. Desplegar automáticamente

## Testing

```bash
# Instalar dependencias de testing
pip install pytest pytest-asyncio httpx

# Ejecutar tests
pytest
```

## Troubleshooting

### Error de conexión a base de datos
- Verificar que PostgreSQL esté ejecutándose
- Confirmar que la URL de conexión sea correcta
- Verificar credenciales de base de datos

### Error de CORS
- Verificar que `FRONTEND_URL` esté configurada correctamente
- Confirmar que el frontend esté ejecutándose en la URL especificada