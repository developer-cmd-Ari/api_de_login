# Nombre de archivo: api_login_v5.py

import os
import sys
import bcrypt
import jwt
import uvicorn
import random
import string
import smtplib
import ssl
import traceback
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, status, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv
from email.header import Header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
from jose import JWTError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

# Cargar variables de entorno desde el archivo .env (para desarrollo local)
load_dotenv()

# --- CONFIGURACIÓN UNIFICADA (Leída desde .env) ---
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
DATABASE_URL = os.getenv('DATABASE_URL') # <-- LA ÚNICA VARIABLE DE CONEXIÓN NECESARIA

# --- Configuración SMTP ---
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
SMTP_USE_SSL = os.getenv('SMTP_USE_SSL', 'False').lower() in ('true', '1', 't')

# --- VALIDACIÓN DE CONFIGURACIÓN ESENCIAL ---
if not JWT_SECRET_KEY:
    raise ValueError("ERROR CRÍTICO: No se encontró JWT_SECRET_KEY en las variables de entorno.")
if not DATABASE_URL:
    raise ValueError("ERROR CRÍTICO: No se encontró DATABASE_URL en las variables de entorno.") # <-- VALIDACIÓN CORRECTA

# Validar Config SMTP (no detiene la app si falta)
smtp_configured = all([SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD])
if not smtp_configured:
     print("*"*60)
     print("ADVERTENCIA: Faltan variables de configuración SMTP. El envío de emails de verificación NO funcionará.")
     print("*"*60)

# --- CONEXIÓN A BASE DE DATOS CON SQLAlchemy ---
try:
    # Render y otros pueden dar una URL que empieza con "postgres://", SQLAlchemy prefiere "postgresql://"
    db_url_sqlalchemy = DATABASE_URL
    if db_url_sqlalchemy.startswith("postgres://"):
        db_url_sqlalchemy = db_url_sqlalchemy.replace("postgres://", "postgresql+psycopg2://", 1)
    
    engine = create_engine(db_url_sqlalchemy)
    
    # Probar la conexión al iniciar
    with engine.connect() as connection:
        print("INFO: Conexión a la base de datos establecida exitosamente.")

except Exception as e:
    print(f"ERROR CRÍTICO al conectar con la base de datos: {e}")
    traceback.print_exc()
    sys.exit(1)

# --- MODELOS Pydantic ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    nombre_usuario: Optional[str] = None # Añadido para el perfil
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

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=8)

class UserProfileResponse(BaseModel):
    nombre_usuario: str
    plan_descripcion: str

# --- Aplicación FastAPI ---
app = FastAPI(
    title="API Login/Registro v2.0 (Render/Neon Ready)",
    description="API unificada con SQLAlchemy para gestionar usuarios, JWT y verificación por correo.",
    version="2.0.0"
)

# --- Configuración de CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Cambiar en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuración Jinja2 para plantillas de email ---
jinja_env = None
try:
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if os.path.isdir(template_dir):
        jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        print(f"INFO: Directorio de plantillas Jinja2 configurado: {template_dir}")
    else:
        print(f"ADVERTENCIA: El directorio de plantillas '{template_dir}' no existe. Emails no funcionarán.")
except Exception as e:
    print(f"ERROR: Configurando Jinja2: {e}")

# --- FUNCIONES HELPER ---

def generar_codigo_verificacion(longitud=6):
    caracteres = string.ascii_uppercase + string.digits
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def enviar_email_verificacion(email_destino: str, codigo: str) -> bool:
    if not smtp_configured or not jinja_env:
        print("ERROR: Email no enviado por falta de configuración SMTP o Jinja2.")
        return False

    asunto = "Código de Verificación para MiApp"
    try:
        template = jinja_env.get_template("verification_email.html")
        html_content = template.render(codigo=codigo, current_year=datetime.now().year)
        
        message = MIMEMultipart("alternative")
        message["Subject"] = Header(asunto, 'utf-8')
        message["From"] = SMTP_SENDER_EMAIL
        message["To"] = email_destino
        message.attach(MIMEText(html_content, "html", "utf-8"))
        
        context = ssl.create_default_context()
        server = None
        print(f"INFO: Intentando enviar email a: {email_destino} via {SMTP_SERVER}:{SMTP_PORT}")
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_SERVER, int(SMTP_PORT), context=context)
        else:
            server = smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT), timeout=10)
            if SMTP_USE_TLS:
                server.starttls(context=context)
        
        server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
        server.sendmail(SMTP_SENDER_EMAIL, destinatario, message.as_bytes())
        print(f"INFO: Email enviado exitosamente a {email_destino}.")
        return True
    except Exception as e:
        print(f"ERROR: Inesperado durante el envío de email a {email_destino}: {e}")
        traceback.print_exc()
        return False
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass

# --- ENDPOINTS ---

@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any], tags=["Autenticación"])
async def register_user(user_data: UserRegister = Body(...)):
    if user_data.zona_id is None and not user_data.zona_nombre_nuevo:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Debe proporcionar 'zona_id' o 'zona_nombre_nuevo'.")
    
    codigo = ""
    with engine.connect() as connection:
        trans = connection.begin()
        try:
            # 1. Verificar email existente
            stmt_check_email = text("SELECT usuario_id FROM usuarios WHERE email = :email")
            if connection.execute(stmt_check_email, {"email": user_data.email}).first():
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="El correo electrónico ya está registrado.")

            # 2. Resolver/Insertar Zona
            id_zona_final = user_data.zona_id
            if id_zona_final is None and user_data.zona_nombre_nuevo:
                nombre_zona_norm = user_data.zona_nombre_nuevo.strip()
                stmt_check_zona = text("SELECT zona_id FROM zonas WHERE nombre = :nombre")
                zona_existente = connection.execute(stmt_check_zona, {"nombre": nombre_zona_norm}).first()
                if zona_existente:
                    id_zona_final = zona_existente.zona_id
                else:
                    stmt_insert_zona = text("INSERT INTO zonas (nombre) VALUES (:nombre) RETURNING zona_id")
                    id_zona_final = connection.execute(stmt_insert_zona, {"nombre": nombre_zona_norm}).scalar_one()

            # 3. Hashear contraseña e insertar usuario
            hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            stmt_insert_user = text("""
                INSERT INTO usuarios (email, contrasena_hash, nombre_usuario, numero_telefono, zona_id, plan_id, email_verificado)
                VALUES (:email, :pass, :nombre, :tel, :zona, :plan, :verif)
                RETURNING usuario_id
            """)
            params_user = {
                "email": user_data.email, "pass": hashed_password, "nombre": user_data.nombre_usuario, 
                "tel": user_data.numero_telefono, "zona": id_zona_final, "plan": 1, "verif": False
            }
            nuevo_usuario_id = connection.execute(stmt_insert_user, params_user).scalar_one()

            # 4. Generar y guardar código de verificación
            codigo = generar_codigo_verificacion()
            expiracion = datetime.now(timezone.utc) + timedelta(minutes=15)
            
            stmt_upsert_code = text("""
                INSERT INTO verificaciones_email (usuario_id, codigo_verificacion, fecha_expiracion)
                VALUES (:uid, :code, :exp)
                ON CONFLICT (usuario_id) DO UPDATE SET
                codigo_verificacion = EXCLUDED.codigo_verificacion,
                fecha_expiracion = EXCLUDED.fecha_expiracion;
            """)
            connection.execute(stmt_upsert_code, {"uid": nuevo_usuario_id, "code": codigo, "exp": expiracion})
            
            trans.commit()
            print(f"|| CÓDIGO DE VERIFICACIÓN PARA {user_data.email}: {codigo} ||")

        except (SQLAlchemyError, HTTPException) as e:
            trans.rollback()
            print(f"ERROR de base de datos en /register: {e}")
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail=f"Error de base de datos durante el registro.")
    
    # 5. Enviar Email (fuera de la transacción)
    if codigo:
        enviar_email_verificacion(user_data.email, codigo)
    
    return {"mensaje": "Usuario registrado. Revisa tu correo o la consola para el código.", "usuario_id": nuevo_usuario_id}


@app.post("/login", response_model=TokenResponse, tags=["Autenticación"])
async def login_user(login_data: UserLogin = Body(...)):
    with engine.connect() as connection:
        stmt = text("SELECT usuario_id, contrasena_hash, email_verificado, plan_id FROM usuarios WHERE email = :email")
        user_row = connection.execute(stmt, {"email": login_data.email}).mappings().first()

        if not user_row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")
        
        if not user_row['email_verificado']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="La cuenta no ha sido verificada.")

        if bcrypt.checkpw(login_data.password.encode('utf-8'), user_row['contrasena_hash'].encode('utf-8')):
            payload = {
                'usuario_id': user_row['usuario_id'],
                'sub': login_data.email,
                'plan_id': user_row['plan_id'],
                'exp': datetime.now(timezone.utc) + timedelta(hours=1)
            }
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            return TokenResponse(mensaje="Login exitoso", token=token, usuario_id=user_row['usuario_id'])
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")


@app.post("/verify-email", response_model=TokenResponse, tags=["Autenticación"])
async def verify_email(verify_data: VerifyEmailRequest = Body(...)):
    with engine.connect() as connection:
        trans = connection.begin()
        try:
            # 1. Buscar usuario y su plan_id
            stmt_get_user = text("SELECT usuario_id, email_verificado, plan_id FROM usuarios WHERE email = :email")
            user_row = connection.execute(stmt_get_user, {"email": verify_data.email}).mappings().first()
            if not user_row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")

            usuario_id = user_row['usuario_id']
            plan_id = user_row['plan_id']

            # 2. Buscar código de verificación
            stmt_get_code = text("SELECT codigo_verificacion, fecha_expiracion FROM verificaciones_email WHERE usuario_id = :uid")
            code_row = connection.execute(stmt_get_code, {"uid": usuario_id}).mappings().first()
            if not code_row:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No se encontró código pendiente.")

            # 3. Comparar código y expiración
            if verify_data.code != code_row['codigo_verificacion']:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Código incorrecto.")
            if datetime.now(timezone.utc) > code_row['fecha_expiracion']:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Código expirado.")

            # 4. Actualizar usuario a verificado
            stmt_update_user = text("UPDATE usuarios SET email_verificado = TRUE WHERE usuario_id = :uid")
            connection.execute(stmt_update_user, {"uid": usuario_id})

            # 5. Borrar código usado
            stmt_delete_code = text("DELETE FROM verificaciones_email WHERE usuario_id = :uid")
            connection.execute(stmt_delete_code, {"uid": usuario_id})

            trans.commit()

            # 6. Generar JWT
            payload = {
                'usuario_id': usuario_id, 'sub': verify_data.email, 'plan_id': plan_id,
                'exp': datetime.now(timezone.utc) + timedelta(hours=1)
            }
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            return TokenResponse(mensaje="Correo verificado. Sesión iniciada.", token=token, usuario_id=usuario_id)

        except (SQLAlchemyError, HTTPException) as e:
            trans.rollback()
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail="Error de base de datos durante la verificación.")


@app.get("/zonas", response_model=List[Zone], tags=["Zonas"])
async def get_zonas(q: Optional[str] = Query(None, min_length=1)):
    with engine.connect() as connection:
        try:
            if q:
                sql_query = text("SELECT zona_id AS id, nombre FROM zonas WHERE nombre ILIKE :search ORDER BY nombre")
                params = {"search": f"%{q}%"}
            else:
                sql_query = text("SELECT zona_id AS id, nombre FROM zonas ORDER BY nombre")
                params = {}
            
            zonas_rows = connection.execute(sql_query, params).mappings().all()
            return zonas_rows
        except SQLAlchemyError as e:
            print(f"ERROR en /zonas: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error al obtener la lista de zonas.")

# --- ENDPOINT DE PERFIL REFACTORIZADO ---
# Dependencia para validar token y obtener datos de usuario
async def get_current_user_data(token: str = Depends(jwt.PyJWT().decode)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas", headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        usuario_id: Optional[int] = payload.get("usuario_id")
        if usuario_id is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception

@app.get("/profile", response_model=UserProfileResponse, tags=["Perfil Usuario"])
async def read_user_profile(current_user_data: Dict[str, Any] = Depends(get_current_user_data)):
    usuario_id = current_user_data.get("usuario_id")
    
    with engine.connect() as connection:
        try:
            sql_query = text("""
                SELECT u.nombre_usuario, p.nombre_plan
                FROM usuarios u
                JOIN planes p ON u.plan_id = p.plan_id
                WHERE u.usuario_id = :uid
            """)
            profile_data = connection.execute(sql_query, {"uid": usuario_id}).mappings().first()

            if not profile_data:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")

            return UserProfileResponse(
             nombre_usuario=profile_data['nombre_usuario'] if profile_data['nombre_usuario'] else "Usuario",
             plan_descripcion=profile_data['nombre_plan'] if profile_data['nombre_plan'] else "desconocido"
            )
        except SQLAlchemyError as e:
            print(f"ERROR en /profile: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno al obtener perfil.")


# --- Bloque para ejecución local con Uvicorn ---
if __name__ == "__main__":
    api_host = os.getenv("API_HOST", "0.0.0.0")
    api_port = int(os.getenv("API_PORT", "8000"))
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    
    print(f"--- Iniciando Servidor FastAPI ---")
    print(f"INFO: Escuchando en: http://{api_host}:{api_port}")
    
    uvicorn.run(f"{script_name}:app", host=api_host, port=api_port, reload=True)