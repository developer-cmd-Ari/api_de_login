# Nombre de archivo sugerido: api_login_v5.py

import os
import psycopg2
import psycopg2.extras # <--- Importante para cursores de diccionario
import bcrypt
import jwt
import uvicorn
import random
import string
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, status, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv
from email.header import Header
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
import traceback
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# --- Configuración (Leída desde .env) ---
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')

# --- CONFIGURACIÓN DE BD SIMPLIFICADA ---
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("No se encontró DATABASE_URL en .env")

# --- Configuración SMTP ---
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
SMTP_USE_SSL = os.getenv('SMTP_USE_SSL', 'False').lower() in ('true', '1', 't')

# --- Validar configuración esencial ---
if not JWT_SECRET_KEY:
    raise ValueError("No se encontró JWT_SECRET_KEY en .env")

smtp_configured = all([SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD])
if not smtp_configured:
     print("*"*60)
     print("ADVERTENCIA: Faltan variables de configuración SMTP.")
     print("*"*60)

# --- Modelos Pydantic (Sin cambios) ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    numero_telefono: Optional[str] = None
    zona_id: Optional[int] = None
    zona_nombre_nuevo: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    mensaje: str
    token: str
    usuario_id: int

class Zone(BaseModel):
    id: int
    nombre: str

class TokenIntrospectRequest(BaseModel):
    token: str

class TokenIntrospectResponse(BaseModel):
    active: bool
    user_id: Optional[int] = None
    email: Optional[EmailStr] = None
    exp: Optional[int] = None

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=8)

# --- Aplicación FastAPI ---
app = FastAPI(
    title="API Login/Registro v2.0 (psycopg2)",
    description="API para gestionar usuarios con Neon DB (PostgreSQL) usando psycopg2.",
    version="2.0.0"
)

# --- CORS (Sin cambios) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- Jinja2 (Sin cambios) ---
try:
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True) if os.path.isdir(template_dir) else None
except Exception as e:
    jinja_env = None

# --- Funciones Auxiliares ---
def crear_conexion_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.Error as ex:
        print(f"ERROR CRÍTICO al conectar a la BD: {ex}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No se pudo conectar a la base de datos.")

def generar_codigo_verificacion(longitud=6):
    caracteres = string.ascii_uppercase + string.digits
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def enviar_email_verificacion(email_destino: str, codigo: str) -> bool:
    # (Esta función no cambia, ya que no interactúa con la BD)
    pass # El código de esta función es largo y no necesita cambios.

# --- Endpoints de la API ---

@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any], tags=["Autenticación"])
async def register_user(user_data: UserRegister = Body(...)):
    if user_data.zona_id is None and not user_data.zona_nombre_nuevo:
        raise HTTPException(status_code=400, detail="Debe proporcionar 'zona_id' o 'zona_nombre_nuevo'.")
    
    conn = None
    cursor = None
    try:
        conn = crear_conexion_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("SELECT usuario_id FROM usuarios WHERE email = %s", (user_data.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="El correo electrónico ya está registrado.")

        id_zona_final = user_data.zona_id
        if id_zona_final is None and user_data.zona_nombre_nuevo:
            nombre_zona_norm = user_data.zona_nombre_nuevo.strip()
            cursor.execute("SELECT zona_id FROM zonas WHERE nombre = %s", (nombre_zona_norm,))
            zona_existente = cursor.fetchone()
            if zona_existente:
                id_zona_final = zona_existente['zona_id']
            else:
                cursor.execute("INSERT INTO zonas (nombre) VALUES (%s) RETURNING zona_id", (nombre_zona_norm,))
                id_zona_final = cursor.fetchone()[0]
        elif id_zona_final:
            cursor.execute("SELECT count(*) FROM zonas WHERE zona_id = %s", (id_zona_final,))
            if cursor.fetchone()[0] == 0:
                raise HTTPException(status_code=400, detail=f"El 'zona_id' {id_zona_final} no existe.")

        cursor.execute("SELECT plan_id FROM planes WHERE nombre = %s", ('Básico',))
        plan_row = cursor.fetchone()
        if not plan_row:
            raise HTTPException(status_code=500, detail="Plan por defecto 'Básico' no encontrado.")
        plan_id_default = plan_row['plan_id']

        hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
        
        sql_insert_user = """
            INSERT INTO usuarios (email, contrasena_hash, numero_telefono, zona_id, plan_id, email_verificado)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING usuario_id
        """
        params_user = (
            user_data.email, hashed_password.decode('utf-8'), user_data.numero_telefono,
            id_zona_final, plan_id_default, 0
        )
        cursor.execute(sql_insert_user, params_user)
        nuevo_usuario_id = cursor.fetchone()[0]

        cursor.execute(
            "INSERT INTO historial_planes_usuario (usuario_id, plan_nuevo_id, motivo) VALUES (%s, %s, %s)",
            (nuevo_usuario_id, plan_id_default, 'Registro inicial')
        )
        
        codigo = generar_codigo_verificacion()
        print(f"|| CÓDIGO PARA {user_data.email}: {codigo} ||")
        expiracion = datetime.now(timezone.utc) + timedelta(minutes=15)
        cursor.execute("DELETE FROM verificaciones_email WHERE usuario_id = %s", (nuevo_usuario_id,))
        cursor.execute(
            "INSERT INTO verificaciones_email (usuario_id, codigo_verificacion, fecha_expiracion) VALUES (%s, %s, %s)",
            (nuevo_usuario_id, codigo, expiracion)
        )
        
        conn.commit()
        
        # enviar_email_verificacion(user_data.email, codigo)
        
        return {"mensaje": "Usuario registrado. Revisa la consola para el código.", "usuario_id": nuevo_usuario_id}
    
    except (Exception, psycopg2.Error) as error:
        if conn:
            conn.rollback()
        print(f"Error en /register: {error}")
        raise HTTPException(status_code=500, detail="Error interno del servidor durante el registro.")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.post("/login", response_model=TokenResponse, tags=["Autenticación"])
async def login_user(login_data: UserLogin = Body(...)):
    # Este bloque ya lo tenías corregido, lo incluimos para que el archivo esté completo.
    conn = None
    try:
        conn = crear_conexion_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (login_data.email,))
        user_row = cursor.fetchone()

        if not user_row or not bcrypt.checkpw(login_data.password.encode('utf-8'), user_row['contrasena_hash'].encode('utf-8')):
            raise HTTPException(status_code=401, detail="Credenciales inválidas.")

        if not user_row['email_verificado']:
            raise HTTPException(status_code=403, detail="La cuenta no ha sido verificada.")
        
        payload = {
            'usuario_id': user_row['usuario_id'],
            'sub': user_row['email'],
            'plan_id': user_row['plan_id'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return TokenResponse(mensaje="Login exitoso", token=token, usuario_id=user_row['usuario_id'])
    
    except (Exception, psycopg2.Error) as error:
        print(f"Error en /login: {error}")
        raise HTTPException(status_code=500, detail="Error interno del servidor durante el login.")
    finally:
        if conn: conn.close()

@app.post("/verify-email", response_model=TokenResponse, tags=["Autenticación"])
async def verify_email(verify_data: VerifyEmailRequest = Body(...)):
    conn = None
    try:
        conn = crear_conexion_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (verify_data.email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")

        cursor.execute("SELECT * FROM verificaciones_email WHERE usuario_id = %s", (user['usuario_id'],))
        code_row = cursor.fetchone()
        if not code_row or code_row['codigo_verificacion'] != verify_data.code:
            raise HTTPException(status_code=400, detail="Código incorrecto.")
        
        if datetime.now(timezone.utc) > code_row['fecha_expiracion'].replace(tzinfo=timezone.utc):
            raise HTTPException(status_code=400, detail="Código expirado.")

        cursor.execute("UPDATE usuarios SET email_verificado = TRUE WHERE usuario_id = %s", (user['usuario_id'],))
        cursor.execute("DELETE FROM verificaciones_email WHERE usuario_id = %s", (user['usuario_id'],))
        
        conn.commit()
        
        payload = {
            'usuario_id': user['usuario_id'],
            'sub': user['email'],
            'plan_id': user['plan_id'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return TokenResponse(mensaje="Correo verificado. Sesión iniciada.", token=token, usuario_id=user['usuario_id'])
    
    except (Exception, psycopg2.Error) as error:
        if conn: conn.rollback()
        print(f"Error en /verify-email: {error}")
        raise HTTPException(status_code=500, detail="Error interno durante la verificación.")
    finally:
        if conn: conn.close()

@app.get("/zonas", response_model=List[Zone], tags=["Zonas"])
async def get_zonas(q: Optional[str] = Query(None, min_length=1)):
    conn = None
    try:
        conn = crear_conexion_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        if q:
            cursor.execute("SELECT zona_id as id, nombre FROM zonas WHERE nombre ILIKE %s ORDER BY nombre", (f"%{q}%",))
        else:
            cursor.execute("SELECT zona_id as id, nombre FROM zonas ORDER BY nombre")
        
        zonas = cursor.fetchall()
        return zonas

    except (Exception, psycopg2.Error) as error:
        print(f"Error en /zonas: {error}")
        raise HTTPException(status_code=500, detail="Error al obtener la lista de zonas.")
    finally:
        if conn: conn.close()

@app.post("/introspect", response_model=TokenIntrospectResponse, tags=["Autenticación"])
async def introspect_token(request_data: TokenIntrospectRequest = Body(...)):
    # (Esta función no cambia, ya que no interactúa con la BD)
    token = request_data.token
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return TokenIntrospectResponse(
            active=True, user_id=payload.get('usuario_id'), email=payload.get('sub'), exp=payload.get('exp')
        )
    except (JWTError, jwt.ExpiredSignatureError):
        return TokenIntrospectResponse(active=False)

# --- Dependencia y endpoint de perfil ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def get_current_active_user_data(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(status_code=401, detail="No se pudieron validar las credenciales")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("usuario_id") is None:
            raise credentials_exception
        return payload
    except (JWTError, jwt.ExpiredSignatureError):
        raise credentials_exception

class UserProfileResponse(BaseModel):
    nombre_usuario: str
    plan_descripcion: str
    plan_id: int

@app.get("/profile", response_model=UserProfileResponse, tags=["Perfil Usuario"])
async def read_user_profile(current_user_data: Dict[str, Any] = Depends(get_current_active_user_data)):
    """
    Devuelve el nombre de usuario y la descripción del plan
    para el usuario actualmente autenticado (basado en el token JWT).
    """
    usuario_id = current_user_data.get("usuario_id")
    if usuario_id is None:
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno: No se pudo obtener ID de usuario del token.")

    print(f"API /profile: Solicitud para usuario_id: {usuario_id}")

    conn = None
    try:
        conn = crear_conexion_db()
        # --- CORRECCIÓN 1: Usar el cursor de diccionario ---
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # La consulta ahora usa JOIN para obtener el nombre del plan
        sql_query = """
            SELECT u.nombre_usuario, p.nombre as plan_descripcion, u.plan_id
            FROM usuarios u
            LEFT JOIN planes p ON u.plan_id = p.plan_id
            WHERE u.usuario_id = %s
        """
        cursor.execute(sql_query, (usuario_id,))
        user_row = cursor.fetchone()

        if not user_row:
            print(f"API /profile Error: Usuario con ID {usuario_id} no encontrado en BD.")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")

        # Ahora el acceso por nombre de columna funcionará correctamente
        nombre_usuario_db = user_row['nombre_usuario']
        plan_descripcion_db = user_row['plan_descripcion'] or "Desconocido"
        plan_id_db = user_row['plan_id']

        print(f"API /profile: Perfil encontrado - Usuario: {nombre_usuario_db}, Plan: {plan_descripcion_db}")

        return UserProfileResponse(
            nombre_usuario=nombre_usuario_db,
            plan_descripcion=plan_descripcion_db,
            plan_id=plan_id_db
        )

    # --- CORRECCIÓN 2: Capturar el error de la librería correcta ---
    except psycopg2.Error as db_err:
        print(f"[ERROR CRÍTICO] Error BD en /profile: {db_err}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno al obtener perfil.")
    except Exception as e:
        print(f"[ERROR CRÍTICO] Error inesperado en /profile: {e}")
        traceback.print_exc()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno inesperado al obtener perfil.")
    finally:
        if conn: conn.close()


if __name__ == "__main__":
    api_host = os.getenv("API_HOST", "0.0.0.0")
    api_port = int(os.getenv("API_PORT", "8001"))
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    uvicorn.run(f"{script_name}:app", host=api_host, port=api_port, reload=True)