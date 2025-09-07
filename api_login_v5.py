# Nombre de archivo sugerido: api_loggin.py

import os
import pyodbc
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
# --- Nuevas Importaciones ---
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
# --- Fin Nuevas Importaciones ---
import traceback # <--- AÑADIR ESTA LÍNEA

from fastapi.security import OAuth2PasswordBearer # Si no lo tenías
from jose import JWTError # Ya deberías tenerlo

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# --- Configuración (Leída desde .env) ---
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')

DB_SERVER = os.getenv('DB_SERVER')
DB_DATABASE = os.getenv('DB_DATABASE')
DB_DRIVER = os.getenv('DB_DRIVER')
DB_CONNECTION_TYPE = os.getenv('DB_CONNECTION_TYPE')
DB_UID = os.getenv('DB_UID')
DB_PWD = os.getenv('DB_PWD')

# --- NUEVO: Configuración SMTP ---
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL')
SMTP_SENDER_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD')
# Convertir strings 'True'/'False' de .env a booleanos
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
SMTP_USE_SSL = os.getenv('SMTP_USE_SSL', 'False').lower() in ('true', '1', 't')
# --- FIN NUEVO ---

# --- Validar configuración esencial ---
if not JWT_SECRET_KEY:
    raise ValueError("No se encontró JWT_SECRET_KEY en .env")
if not DB_SERVER or not DB_DATABASE or not DB_DRIVER:
     raise ValueError("Faltan variables de configuración de base de datos en .env")
# --- NUEVO: Validar Config SMTP ---
smtp_configured = all([SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD])
if not smtp_configured:
     print("*"*60)
     print("ADVERTENCIA: Faltan variables de configuración SMTP en .env.")
     print("El envío de emails de verificación NO funcionará.")
     print("Asegúrate de definir: SMTP_SERVER, SMTP_PORT, SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD")
     print("*"*60)
# --- FIN NUEVO ---

# --- Construir la cadena de conexión ---
CONNECTION_STRING = ""
if DB_CONNECTION_TYPE == 'WINDOWS':
    CONNECTION_STRING = f"DRIVER={DB_DRIVER};SERVER={DB_SERVER};DATABASE={DB_DATABASE};Trusted_Connection=yes;"
elif DB_CONNECTION_TYPE == 'SQL':
    if not DB_UID or not DB_PWD:
        raise ValueError("Se requiere DB_UID y DB_PWD para la autenticación SQL en .env")
    CONNECTION_STRING = f"DRIVER={DB_DRIVER};SERVER={DB_SERVER};DATABASE={DB_DATABASE};UID={DB_UID};PWD={DB_PWD};"
else:
    raise ValueError("DB_CONNECTION_TYPE debe ser 'WINDOWS' o 'SQL' en .env")

print(f"Cadena Conexión (verificación): DRIVER={DB_DRIVER};SERVER={DB_SERVER};DATABASE={DB_DATABASE};...") # Ocultar UID/PWD en logs reales

# --- Modelos Pydantic ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    numero_telefono: Optional[str] = None
    zona_id: Optional[int] = None
    zona_nombre_nuevo: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel): # Usado por /login y /verify-email
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
    code: str = Field(..., min_length=4, max_length=8) # Ajusta longitud si es necesario

# --- Aplicación FastAPI ---
app = FastAPI(
    title="API Login/Registro v1.5 (con OUTPUT clause)",
    description="API para gestionar usuarios, autenticación JWT (HS256) y verificación de correo real vía SMTP. Usa OUTPUT para obtener IDs.",
    version="1.5.0"
)

# --- Configuración de CORS ---
origins = ["*"] # ¡¡¡CAMBIAR EN PRODUCCIÓN!!! Restringir a dominios específicos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- Configuración Jinja2 ---
try:
    # Asume que la carpeta 'templates' está al mismo nivel que este script
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if not os.path.isdir(template_dir):
        print(f"ADVERTENCIA: El directorio de plantillas '{template_dir}' no existe.")
        jinja_env = None
    else:
        jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
        print(f"Directorio de plantillas Jinja2 configurado: {template_dir}")
except Exception as e:
    print(f"Error crítico al configurar Jinja2: {e}")
    jinja_env = None # Marcar como no disponible si falla

# --- Funciones Auxiliares ---
def crear_conexion_db():
    """Intenta crear y devolver una conexión a la BD."""
    try:
        # print("Intentando conectar a BD...") # Comentar en producción
        conn = pyodbc.connect(CONNECTION_STRING, autocommit=False)
        # print("Conexión a BD establecida.") # Comentar en producción
        return conn
    except pyodbc.Error as ex:
        sqlstate = ex.args[0]; message = ex.args[1]
        print(f"ERROR CRÍTICO al conectar a la BD: SQLSTATE={sqlstate}, Mensaje={message}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No se pudo conectar a la base de datos.")
    except Exception as e:
        print(f"ERROR INESPERADO al conectar a la BD: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno del servidor al conectar a la BD.")

def generar_codigo_verificacion(longitud=6):
    """Genera un código alfanumérico aleatorio."""
    caracteres = string.ascii_uppercase + string.digits
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def enviar_email_verificacion(email_destino: str, codigo: str) -> bool:
    """
    Envía el email de verificación usando SMTP y una plantilla Jinja2 HTML.
    Maneja correctamente la codificación UTF-8 para caracteres especiales.
    Devuelve True si el envío fue exitoso, False si falló.
    """
    if not smtp_configured:
        print("ERROR: Intento de envío de email SIN configuración SMTP completa.")
        return False
    if not jinja_env:
        print("ERROR: Intento de envío de email SIN entorno Jinja2 configurado.")
        return False

    asunto = "Código de Verificación para MiApp" # Contiene 'ó'
    remitente = SMTP_SENDER_EMAIL
    destinatario = email_destino

    try:
        # Renderizar plantilla HTML (asumiendo que el template está en UTF-8)
        template = jinja_env.get_template("verification_email.html")
        current_year = datetime.now().year
        html_content = template.render(codigo=codigo, current_year=current_year)

        # Crear mensaje MIME
        message = MIMEMultipart("alternative")

        # --- MODIFICADO: Codificar cabeceras ---
        message["Subject"] = Header(asunto, 'utf-8') # Codifica el asunto
        message["From"] = remitente # Las direcciones de email suelen ser ASCII
        message["To"] = destinatario # Ídem
        # --- FIN MODIFICADO ---

        # --- MODIFICADO: Especificar UTF-8 para el cuerpo HTML ---
        # Adjuntar parte HTML especificando explícitamente utf-8
        message.attach(MIMEText(html_content, "html", "utf-8"))
        # --- FIN MODIFICADO ---

        # Conectar y enviar (sin cambios en esta parte)
        context = ssl.create_default_context()
        server = None

        print(f"Intentando enviar email a: {destinatario} via {SMTP_SERVER}:{SMTP_PORT}")
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_SERVER, int(SMTP_PORT), context=context)
        else:
            server = smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT), timeout=10)
            if SMTP_USE_TLS:
                server.starttls(context=context)

        server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_PASSWORD)
        # sendmail necesita el mensaje como bytes, as_bytes() es mejor que as_string()
        # para manejar correctamente la codificación especificada.
        server.sendmail(remitente, destinatario, message.as_bytes()) # Usar as_bytes()
        print(f"Email enviado exitosamente a {destinatario}.")
        return True

    except FileNotFoundError:
         print(f"ERROR CRÍTICO: No se encontró la plantilla 'verification_email.html' en '{template_dir}'.")
         return False
    except smtplib.SMTPAuthenticationError:
        print(f"ERROR SMTP: Falló la autenticación para {SMTP_SENDER_EMAIL}. Verifica email/contraseña/permisos.")
        # ¡Aquí es donde fallaría si las credenciales en .env son incorrectas!
        return False
    except smtplib.SMTPException as e:
        print(f"ERROR SMTP: {e}")
        return False
    except Exception as e:
        print(f"Error inesperado durante el envío de email a {destinatario}: {e}")
        import traceback
        traceback.print_exc() # Imprimir traceback completo para errores inesperados
        return False
    finally:
        if server:
            try:
                server.quit()
            except Exception as e:
                 print(f"Advertencia: Error menor al cerrar conexión SMTP: {e}")

# --- Endpoints de la API ---

@app.post("/register", status_code=status.HTTP_201_CREATED,
          response_model=Dict[str, Any], # Devuelve dict porque no hay token aún
          summary="Registra usuario, envía código (usa OUTPUT clause)", tags=["Autenticación"])
async def register_user(user_data: UserRegister = Body(...)):
    """
    Registra un nuevo usuario usando OUTPUT INSERTED.usuario_id para obtener el ID.
    Intenta enviar un correo de verificación real (ignora fallo para la respuesta).
    IMPRIME el código de verificación en la consola para pruebas.
    Manejo explícito de conexión.
    """
    if user_data.zona_id is None and not user_data.zona_nombre_nuevo:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Debe proporcionar 'zona_id' o 'zona_nombre_nuevo'.")

    conn = None
    cursor = None
    nuevo_usuario_id = None
    commit_exitoso = False # Para controlar rollback en except

    try:
        conn = crear_conexion_db()
        cursor = conn.cursor()
        # print("[Register] Conexión y cursor creados.") # DEBUG

        # 1. Verificar email existente
        # print(f"[Register] Verificando email: {user_data.email}") # DEBUG
        cursor.execute("SELECT usuario_id FROM usuarios WHERE email = ?", (user_data.email,)) # Optimizado: solo pide ID si existe
        existing_user = cursor.fetchone()
        if existing_user:
            # print(f"[Register] Email {user_data.email} ya existe (ID: {existing_user[0]}).") # DEBUG
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="El correo electrónico ya está registrado.")

        # 2. Resolver/Insertar Zona (usando SCOPE_IDENTITY para nueva zona)
        id_zona_final = user_data.zona_id
        # print(f"[Register] Resolviendo zona: id={id_zona_final}, nombre={user_data.zona_nombre_nuevo}") # DEBUG
        if id_zona_final is None and user_data.zona_nombre_nuevo:
            # Normalizar nombre de zona (ej: quitar espacios extra, capitalizar?)
            nombre_zona_norm = user_data.zona_nombre_nuevo.strip()
            cursor.execute("SELECT zona_id FROM zonas WHERE nombre = ?", (nombre_zona_norm,))
            zona_existente = cursor.fetchone()
            if zona_existente:
                id_zona_final = zona_existente[0]
                # print(f"[Register] Zona encontrada por nombre '{nombre_zona_norm}'. ID: {id_zona_final}") # DEBUG
            else:
                # print(f"[Register] Insertando nueva zona: {nombre_zona_norm}") # DEBUG
                # Asumiendo que 'descripcion' es NULL por defecto en la tabla zonas
                cursor.execute("INSERT INTO zonas (nombre) VALUES (?)", (nombre_zona_norm,))
                cursor.execute("SELECT SCOPE_IDENTITY()") # Usamos SCOPE_IDENTITY para zona ID
                scope_id_zona = cursor.fetchval() # fetchval() es más directo para un solo valor
                if scope_id_zona is None:
                    if conn: conn.rollback()
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo obtener el ID de la nueva zona insertada.")
                id_zona_final = int(scope_id_zona)
                # print(f"[Register] Nueva zona insertada con ID: {id_zona_final}") # DEBUG
        elif id_zona_final:
             # Opcional: Validar que la zona_id proporcionada exista en la tabla zonas
             cursor.execute("SELECT COUNT(*) FROM zonas WHERE zona_id = ?", (id_zona_final,))
             if cursor.fetchval() == 0:
                 raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"El 'zona_id' {id_zona_final} proporcionado no existe.")
             # print(f"[Register] Usando zona_id proporcionado: {id_zona_final}") # DEBUG

        # 3. Obtener Plan Básico ID
        # print("[Register] Buscando plan 'Básico'...") # DEBUG
        cursor.execute("SELECT plan_id FROM planes WHERE nombre = ?", ('Básico',))
        plan_row = cursor.fetchone()
        if not plan_row:
            print("[Register] ERROR CRÍTICO: Plan 'Básico' no encontrado en DB.")
            if conn: conn.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Configuración interna: Plan por defecto 'Básico' no encontrado.")
        plan_id_default = plan_row[0]
        # print(f"[Register] Plan 'Básico' encontrado. ID: {plan_id_default}") # DEBUG

        # 4. Hashear Password
        hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
        # print("[Register] Contraseña hasheada.") # DEBUG

        # 5. Insertar Usuario Y OBTENER EL ID DIRECTAMENTE CON OUTPUT
        # Modificamos la SQL para incluir la cláusula OUTPUT
        sql_insert_user_with_output = """
            INSERT INTO usuarios (email, contrasena_hash, numero_telefono, zona_id, plan_id, email_verificado)
            OUTPUT INSERTED.usuario_id  -- <--- Devuelve el ID insertado
            VALUES (?, ?, ?, ?, ?, ?)
        """
        params_user = (
             user_data.email, hashed_password.decode('utf-8'), user_data.numero_telefono,
             id_zona_final, plan_id_default, 0 # email_verificado = False (0)
        )
        # print(f"[DEBUG] Ejecutando INSERT usuarios con OUTPUT para: {user_data.email}") # DEBUG

        # Ejecutar el INSERT y obtener el ID directamente
        try:
            # fetchval() funciona porque OUTPUT devuelve una sola columna y (esperamos) una sola fila
            nuevo_usuario_id_obj = cursor.execute(sql_insert_user_with_output, params_user).fetchval()
        except pyodbc.Error as insert_err:
            # Capturar error específico del INSERT con OUTPUT
            print(f"[ERROR CRÍTICO] Falló el INSERT con OUTPUT para {user_data.email}. Error: {insert_err}")
            if conn: conn.rollback() # Intentar rollback si el insert falla
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Fallo al insertar el usuario en la base de datos.")

        # print(f"[DEBUG] Resultado de fetchval() para INSERT con OUTPUT: {nuevo_usuario_id_obj}") # DEBUG

        # Verificar si obtuvimos un ID
        if nuevo_usuario_id_obj is None:
            print(f"[ERROR CRÍTICO] INSERT con OUTPUT devolvió None para usuario {user_data.email}. ¿El INSERT falló silenciosamente o OUTPUT no está configurado?")
            # Si OUTPUT falla, es un problema serio. Puede indicar triggers complejos o problemas con la sesión/driver.
            if conn: conn.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo obtener el ID del usuario después de insertarlo (OUTPUT devolvió None).")

        nuevo_usuario_id = int(nuevo_usuario_id_obj)
        # --- FIN DEL CAMBIO A OUTPUT ---
        print(f"[INFO] Usuario '{user_data.email}' insertado con ID: {nuevo_usuario_id} (obtenido con OUTPUT)")


        # 6. Insertar Historial
        # print(f"[Register] Insertando historial para usuario ID: {nuevo_usuario_id}") # DEBUG
        # Tu tabla historial_planes_usuario tiene DEFAULT para fecha_cambio
        sql_insert_historial = "INSERT INTO historial_planes_usuario (usuario_id, plan_anterior_id, plan_nuevo_id, motivo) VALUES (?, NULL, ?, ?)"
        cursor.execute(sql_insert_historial, (nuevo_usuario_id, plan_id_default, 'Registro inicial'))

        # 7. LÓGICA DE CÓDIGO DE VERIFICACIÓN (antes del commit)
        # print(f"[Register] Preparando código de verificación para usuario ID: {nuevo_usuario_id}") # DEBUG
        codigo = generar_codigo_verificacion()

        # --- ¡NUEVO! Imprimir código en la consola ---
        print("="*70)
        print(f"|| CÓDIGO DE VERIFICACIÓN GENERADO PARA {user_data.email}: {codigo} ||")
        print("="*70)
        # --- FIN NUEVO ---

        expiracion = datetime.now(timezone.utc) + timedelta(minutes=15) # UTC
        # print(f"[Register] Eliminando código de verificación antiguo (si existe) para usuario ID: {nuevo_usuario_id}") # DEBUG
        cursor.execute("DELETE FROM verificaciones_email WHERE usuario_id = ?", (nuevo_usuario_id,))
        # print(f"[Register] Insertando nuevo código de verificación para usuario ID: {nuevo_usuario_id}") # DEBUG
        sql_insert_codigo = "INSERT INTO verificaciones_email (usuario_id, codigo_verificacion, fecha_expiracion) VALUES (?, ?, ?)"
        cursor.execute(sql_insert_codigo, (nuevo_usuario_id, codigo, expiracion))
        # print(f"[Register] Código de verificación '{codigo}' preparado.") # DEBUG

        # 8. Commit Final (Incluye todo: usuario, historial, código)
        # print(f"[Register] Realizando commit final para usuario ID: {nuevo_usuario_id}") # DEBUG
        conn.commit()
        commit_exitoso = True
        print(f"[INFO] Commit exitoso para registro de usuario ID: {nuevo_usuario_id}")

        # 9. Intentar Enviar Email (PERO IGNORAR EL FALLO PARA LA RESPUESTA FINAL)
        print(f"[Register] Intentando enviar email de verificación a {user_data.email} (se ignorará fallo)...") # INFO
        email_enviado = enviar_email_verificacion(user_data.email, codigo)

        # --- MODIFICADO: Solo advertir si falla, no afecta la respuesta ---
        if not email_enviado:
            print(f"ADVERTENCIA (IGNORADA): El email de verificación para {user_data.email} (ID: {nuevo_usuario_id}) NO PUDO SER ENVIADO.")
            print("             (El código se mostró en consola para pruebas).")
        # --- FIN MODIFICADO ---

        # Devolver solo mensaje estándar, SIN TOKEN (incluso si el email falló)
        # Ajustar el mensaje para indicar que el código también está en consola
        return {"mensaje": "Usuario registrado. Revisa tu correo O LA CONSOLA para obtener el código de verificación.", "usuario_id": nuevo_usuario_id}

    # --- Bloques Except (Sin cambios) ---
    except HTTPException as http_err:
        # Loggear el detalle de la excepción HTTP
        print(f"[WARN] HTTPException en /register: {http_err.status_code} - {http_err.detail}")
        if conn and not commit_exitoso:
            try:
                conn.rollback()
                print("[INFO] Rollback realizado por HTTPException pre-commit.")
            except Exception as roll_err:
                print(f"[ERROR] Error durante rollback por HTTPException: {roll_err}")
        raise http_err # Re-lanzar para que FastAPI la maneje

    except pyodbc.Error as db_err:
        # Loggear el error de base de datos específico
        err_msg = f"SQLSTATE: {db_err.args[0]} - Mensaje: {db_err.args[1]}"
        print(f"[ERROR CRÍTICO] Error de Base de Datos en /register: {err_msg}")
        if conn and not commit_exitoso:
            try:
                conn.rollback()
                print("[INFO] Rollback realizado por pyodbc.Error pre-commit.")
            except Exception as roll_err:
                print(f"[ERROR] Error durante rollback por pyodbc.Error: {roll_err}")
        # Devolver un error genérico al cliente
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error interno del servidor al procesar el registro.")

    except Exception as e:
        # Capturar cualquier otro error inesperado
        print(f"[ERROR CRÍTICO] Error inesperado en /register: {e}")
        # Considerar loggear el traceback completo
        import traceback
        traceback.print_exc()
        if conn and not commit_exitoso:
            try:
                conn.rollback()
                print("[INFO] Rollback realizado por Exception pre-commit.")
            except Exception as roll_err:
                print(f"[ERROR] Error durante rollback por Exception: {roll_err}")
        # Devolver un error genérico al cliente
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error interno inesperado durante el registro.")

    finally:
        # Asegurar cierre de recursos
        if cursor:
            try:
                cursor.close()
                # print("Cursor cerrado en register_user.") # DEBUG
            except Exception as cur_err:
                print(f"[ERROR] Error al cerrar cursor en register_user: {cur_err}")
        if conn:
            try:
                conn.close()
                # print("Conexión cerrada en register_user.") # DEBUG
            except Exception as conn_err:
                print(f"[ERROR] Error al cerrar conexión en register_user: {conn_err}")


@app.post("/login", response_model=TokenResponse, tags=["Autenticación"])
async def login_user(login_data: UserLogin = Body(...)):
    """ Autentica usuario. Requiere email_verificado = 1. INCLUYE plan_id en JWT. """
    conn = None; cursor = None
    try:
        conn = crear_conexion_db(); cursor = conn.cursor()
        # --- MODIFICADO: Seleccionar también plan_id ---
        sql_query = "SELECT usuario_id, contrasena_hash, email_verificado, plan_id FROM usuarios WHERE email = ?"
        cursor.execute(sql_query, (login_data.email,))
        user_row = cursor.fetchone()

        if not user_row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")

        usuario_id = user_row[0]
        stored_hash = user_row[1].encode('utf-8')
        verificado = bool(user_row[2])
        plan_id = user_row[3] # <-- Obtener plan_id

        # Validar si plan_id es None (no debería si la columna es NOT NULL)
        if plan_id is None:
             print(f"[Login ERROR] Usuario {login_data.email} (ID: {usuario_id}) no tiene plan_id asignado en la BD.")
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno: Falta información del plan de usuario.")

        if not verificado:
            print(f"[Login Attempt] Usuario {login_data.email} (ID: {usuario_id}) intentó login SIN verificar email.")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="La cuenta no ha sido verificada.")

        if bcrypt.checkpw(login_data.password.encode('utf-8'), stored_hash):
            # Contraseña válida, generar token CON plan_id
            payload = {
                'usuario_id': usuario_id,
                'sub': login_data.email, # 'sub' es el claim estándar para "subject" (usualmente username/email)
                'plan_id': plan_id, # <-- AÑADIDO plan_id al payload
                'exp': datetime.now(timezone.utc) + timedelta(hours=1) # Token expira en 1 hora (ajusta si necesitas)
            }
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            print(f"[Login Success] User {login_data.email} (ID: {usuario_id}, Plan: {plan_id}) logged in.")
            # La respuesta no necesita incluir plan_id, ya va en el token
            return TokenResponse(mensaje="Login exitoso", token=token, usuario_id=usuario_id)
        else:
            print(f"[Login Attempt] Contraseña inválida para user {login_data.email} (ID: {usuario_id}).")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")

    except HTTPException as http_err:
        # Re-lanzar excepciones HTTP ya manejadas
        raise http_err
    except pyodbc.Error as db_err:
        err_msg = f"SQLSTATE: {db_err.args[0]} - Mensaje: {db_err.args[1]}"
        print(f"[ERROR CRÍTICO] Error de Base de Datos en /login: {err_msg}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno del servidor durante el login.")
    except Exception as e:
        print(f"[ERROR CRÍTICO] Error inesperado en /login: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno inesperado durante el login.")
    finally:
         if cursor: cursor.close() # print("Cursor cerrado login.")
         if conn: conn.close() # print("Conexión cerrada login.")


@app.post("/verify-email", response_model=TokenResponse, summary="Verifica código y activa cuenta", tags=["Autenticación"])
async def verify_email(verify_data: VerifyEmailRequest = Body(...)):
    """ Valida código, activa cuenta y devuelve JWT CON plan_id. """
    conn = None; cursor = None; commit_exitoso = False; usuario_id = None; plan_id = None # Inicializar plan_id

    try:
        conn = crear_conexion_db(); cursor = conn.cursor()

        # 1. Buscar usuario, estado y ¡plan_id!
        # --- MODIFICADO: Seleccionar también plan_id ---
        sql_get_user = "SELECT usuario_id, email_verificado, plan_id FROM usuarios WHERE email = ?"
        cursor.execute(sql_get_user, (verify_data.email,))
        user_row = cursor.fetchone()
        if not user_row: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")

        usuario_id = user_row[0]
        estaba_verificado = bool(user_row[1])
        plan_id = user_row[2] # <-- Obtener plan_id

        # Validar si plan_id es None
        if plan_id is None:
             print(f"[Verify ERROR] Usuario {verify_data.email} (ID: {usuario_id}) no tiene plan_id asignado en la BD.")
             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno: Falta información del plan de usuario.")

        if estaba_verificado: print(f"[Verify INFO] Email {verify_data.email} (ID: {usuario_id}) ya estaba verificado.")

        # 2. Buscar código de verificación
        # ... (código para buscar code_row igual que antes) ...
        sql_get_code = "SELECT codigo_verificacion, fecha_expiracion FROM verificaciones_email WHERE usuario_id = ?"
        cursor.execute(sql_get_code, (usuario_id,))
        code_row = cursor.fetchone()
        if not code_row: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No se encontró código pendiente (¿expirado o ya usado?).")

        stored_code = code_row[0]
        expires_at_from_db = code_row[1]

        # 3. Comparar código y expiración
        if verify_data.code != stored_code: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Código incorrecto.")
        if not isinstance(expires_at_from_db, datetime): raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error fecha expiración.")
        expires_at_utc = expires_at_from_db.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at_utc: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Código expirado.")

        print(f"[Verify INFO] Código válido para user {verify_data.email} (ID: {usuario_id})")

        # 4. Actualizar usuario (si no estaba verificado)
        # 4. Actualizar usuario (si no estaba verificado)
        if not estaba_verificado:
         sql_update_user = "UPDATE usuarios SET email_verificado = 1 WHERE usuario_id = ?"
        cursor.execute(sql_update_user, (usuario_id,))

        # --- INICIO SECCIÓN CORREGIDA ---
        if cursor.rowcount != 1:
            # Imprime el mensaje crítico
            print(f"[ERROR CRÍTICO] No se actualizó el estado de verificación para el usuario ID {usuario_id} (rowcount: {cursor.rowcount})")
            # Intenta hacer rollback si la conexión existe
            if conn:
                try:
                    print("[Verify WARN] Intentando rollback debido a rowcount inesperado...")
                    conn.rollback()
                    print("[Verify WARN] Rollback realizado.")
                except Exception as roll_err:
                    # Loggear si el rollback falla, pero la excepción principal sigue siendo la de abajo
                    print(f"[ERROR CRÍTICO] Falla durante el rollback tras error de rowcount: {roll_err}")
            # Siempre lanza la excepción si rowcount no fue 1
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno crítico al actualizar la verificación del usuario."
            )
        # --- FIN SECCIÓN CORREGIDA ---

        print(f"[Verify INFO] User {verify_data.email} (ID: {usuario_id}) marcado como verificado.")

        # 5. Borrar código usado
        sql_delete_code = "DELETE FROM verificaciones_email WHERE usuario_id = ?"
        cursor.execute(sql_delete_code, (usuario_id,))
        if cursor.rowcount == 0: print(f"[Verify WARN] No se borró código para user ID {usuario_id} (¿ya borrado?).")

        # 6. Commit
        conn.commit(); commit_exitoso = True
        print(f"[INFO] Commit OK para verificación user ID: {usuario_id}")

        # 7. Generar JWT incluyendo plan_id
        print(f"[Verify] Generando JWT para user ID: {usuario_id} con Plan ID: {plan_id}")
        payload = {
            'usuario_id': usuario_id,
            'sub': verify_data.email,
            'plan_id': plan_id, # <-- AÑADIDO plan_id al payload
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        return TokenResponse(
            mensaje="Correo verificado. Sesión iniciada.",
            token=token,
            usuario_id=usuario_id
        )

    # --- Bloques Except y Finally (Sin cambios en la lógica) ---
    except HTTPException as http_err:
        print(f"[WARN] HTTPException en /verify-email: {http_err.status_code} - {http_err.detail}")
        if conn and not commit_exitoso:
            try: conn.rollback(); print("[INFO] Rollback realizado por HTTPException pre-commit (verify).")
            except Exception as roll_err: print(f"[ERROR] Error durante rollback por HTTPException (verify): {roll_err}")
        raise http_err
    except pyodbc.Error as db_err:
        err_msg = f"SQLSTATE: {db_err.args[0]} - Mensaje: {db_err.args[1]}"
        print(f"[ERROR CRÍTICO] Error de Base de Datos en /verify-email: {err_msg}")
        if conn and not commit_exitoso:
            try: conn.rollback(); print("[INFO] Rollback realizado por pyodbc.Error pre-commit (verify).")
            except Exception as roll_err: print(f"[ERROR] Error durante rollback por pyodbc.Error (verify): {roll_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno del servidor durante la verificación.")
    except Exception as e:
        print(f"[ERROR CRÍTICO] Error inesperado en /verify-email: {e}")
        import traceback
        traceback.print_exc()
        if conn and not commit_exitoso:
            try: conn.rollback(); print("[INFO] Rollback realizado por Exception pre-commit (verify).")
            except Exception as roll_err: print(f"[ERROR] Error durante rollback por Exception (verify): {roll_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno inesperado durante la verificación.")
    finally:
        if cursor: cursor.close() # print("Cursor cerrado verify.")
        if conn: conn.close() # print("Conexión cerrada verify.")


@app.get("/zonas", response_model=List[Zone], tags=["Zonas"])
async def get_zonas(q: Optional[str] = Query(None, min_length=1, max_length=50, description="Texto para filtrar zonas por nombre (parcial)")):
    """ Devuelve una lista de zonas, opcionalmente filtrada por nombre. """
    conn = None; cursor = None
    try:
        conn = crear_conexion_db(); cursor = conn.cursor()
        if q:
            sql_query = "SELECT zona_id, nombre FROM zonas WHERE nombre LIKE ? ORDER BY nombre"
            # Añadir wildcards para búsqueda parcial
            search_pattern = f"%{q}%"
            cursor.execute(sql_query, (search_pattern,))
        else:
            # Devolver todas las zonas si no hay query 'q'
            sql_query = "SELECT zona_id, nombre FROM zonas ORDER BY nombre"
            cursor.execute(sql_query)

        zonas_rows = cursor.fetchall()
        # Convertir las filas de la BD (tuples) a objetos compatibles con el modelo Pydantic Zone
        # Asumiendo que pyodbc devuelve objetos row con acceso por nombre de columna
        zonas_list = [{"id": row.zona_id, "nombre": row.nombre} for row in zonas_rows]
        return zonas_list

    except pyodbc.Error as db_err:
        err_msg = f"SQLSTATE: {db_err.args[0]} - Mensaje: {db_err.args[1]}"
        print(f"[ERROR] Error de Base de Datos en /zonas: {err_msg}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error al obtener la lista de zonas.")
    except Exception as e:
        print(f"[ERROR] Error inesperado en /zonas: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error inesperado al obtener las zonas.")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# En api_login_v5.py (o como se llame tu API de Login/Auth)

# ... (importaciones y definición de TokenIntrospectRequest/Response) ...

@app.post("/introspect", response_model=TokenIntrospectResponse, tags=["Autenticación"])
async def introspect_token(request_data: TokenIntrospectRequest = Body(...)):
    """
    Valida un token JWT internamente (firma, expiración).
    (CON DEBUG PRINTS)
    """
    # --- DEBUG PRINTS ---
    print("=" * 20 + " Endpoint /introspect (Login API) INVOCADO " + "=" * 20)
    print(f"-> Cuerpo de la solicitud recibida: {request_data}")
    # --------------------

    token = request_data.token
    if not token:
        print("-> ERROR: Token no encontrado en request_data.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token no proporcionado en la solicitud.")

    print(f"-> Token extraído para validar: {token[:5]}...{token[-5:]}")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )
        user_id = payload.get('user_id')
        email = payload.get('email') # o payload.get('sub') si usas 'sub'
        exp_timestamp = payload.get('exp')
        print(f"-> Validación JWT exitosa. UserID: {user_id}, Email: {email}")
        print("-> DECISIÓN: Respondiendo active: True")
        print("=" * 20 + " Fin /introspect (Login API) " + "=" * 20)
        return TokenIntrospectResponse(
            active=True, user_id=user_id, email=email, exp=exp_timestamp
        )
    except jwt.ExpiredSignatureError:
        print("-> Validación JWT fallida: Token expirado.")
        print("-> DECISIÓN: Respondiendo active: False")
        print("=" * 20 + " Fin /introspect (Login API) " + "=" * 20)
        return TokenIntrospectResponse(active=False)
    except jwt.InvalidTokenError as e:
        print(f"-> Validación JWT fallida: Token inválido ({e}).")
        print("-> DECISIÓN: Respondiendo active: False")
        print("=" * 20 + " Fin /introspect (Login API) " + "=" * 20)
        return TokenIntrospectResponse(active=False)
    except Exception as e:
        print(f"-> ERROR inesperado decodificando token: {e}")
        import traceback; traceback.print_exc()
        print("-> DECISIÓN: Respondiendo active: False (por seguridad)")
        print("=" * 20 + " Fin /introspect (Login API) " + "=" * 20)
        return TokenIntrospectResponse(active=False)

# --- Bloque para ejecución directa con Uvicorn (para desarrollo) ---
#     Asegúrate que el nombre del archivo es 'api_loggin.py' o ajusta el string.
#     En producción, es mejor usar un gestor como Gunicorn + Uvicorn workers.
if __name__ == "__main__":
    print("Iniciando servidor FastAPI con Uvicorn...")
    # Extraer host y port de variables de entorno si existen, sino usar defaults
    # Usa 0.0.0.0 para que sea accesible desde otras máquinas en la red local
    api_host = os.getenv("API_HOST", "0.0.0.0")
    api_port = int(os.getenv("API_PORT", "8000")) # Default a 8000

    print(f"Servidor escuchando en http://{api_host}:{api_port}")
    # reload=True es útil para desarrollo, desactivar en producción
    # Asegúrate que el primer argumento coincide con el nombre de tu archivo python
    # Por ejemplo, si tu archivo se llama mi_api.py, usa "mi_api:app"
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    uvicorn.run(f"{script_name}:app", host=api_host, port=api_port, reload=True)
    
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login") # Ajusta la URL si es diferente

async def get_current_active_user_data(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Dependencia FastAPI para validar un token JWT y extraer los datos del payload.
    Devuelve un diccionario con los claims del token si es válido.
    Lanza HTTPException 401 si el token es inválido o expirado.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decodifica y valida el token (firma, expiración, algoritmo)
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY, # Tu clave secreta desde .env
            algorithms=[JWT_ALGORITHM] # Tu algoritmo desde .env
        )

        # Extrae la información que necesitas (ajusta según lo que guardes en el token)
        usuario_id: Optional[int] = payload.get("usuario_id")
        email: Optional[str] = payload.get("sub") # 'sub' es estándar para email/username

        if usuario_id is None:
            print("[Auth Dep Error] usuario_id no encontrado en el payload del token.")
            raise credentials_exception

        # Podrías añadir una verificación opcional aquí para ver si el usuario_id
        # todavía existe en la BD, pero para este endpoint puede bastar con el token.

        print(f"[Auth Dep OK] Token válido para usuario_id: {usuario_id}, email: {email}")
        # Devuelve el payload o un diccionario con los datos necesarios
        return {"usuario_id": usuario_id, "email": email, **payload} # Devuelve todo el payload

    except jwt.ExpiredSignatureError:
        print("[Auth Dep Warn] Token expirado.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token ha expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e: # Captura otros errores de JWT (firma inválida, etc.)
        print(f"[Auth Dep Error] Error de Token JWT: {e}")
        raise credentials_exception
    except Exception as e: # Captura cualquier otro error inesperado
         print(f"[Auth Dep Error] Error inesperado en dependencia de autenticación: {e}")
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno al procesar autenticación: {e}"
         )
class UserProfileResponse(BaseModel):
    """Esquema Pydantic para la respuesta del perfil de usuario."""
    nombre_usuario: str
    plan_descripcion: str

# --- Nuevo Endpoint ---
@app.get("/profile", response_model=UserProfileResponse, summary="Obtiene perfil del usuario autenticado", tags=["Perfil Usuario"])
async def read_user_profile(
    current_user_data: Dict[str, Any] = Depends(get_current_active_user_data) # Usa la dependencia
):
    """
    Devuelve el nombre de usuario y la descripción del plan
    para el usuario actualmente autenticado (basado en el token JWT).
    """
    usuario_id = current_user_data.get("usuario_id")
    if usuario_id is None: # Doble chequeo por si la dependencia fallara
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno: No se pudo obtener ID de usuario del token.")

    print(f"API /profile: Solicitud para usuario_id: {usuario_id}")

    conn = None
    cursor = None
    try:
        conn = crear_conexion_db()
        cursor = conn.cursor()

        # --- Consulta a la BD para obtener nombre_usuario y plan_id ---
        # ¡ASEGÚRATE que tu tabla se llame 'usuarios' y las columnas 'usuario_id', 'nombre_usuario', 'plan_id'!
        sql_query = "SELECT nombre_usuario, plan_id FROM usuarios WHERE usuario_id = ?"
        cursor.execute(sql_query, (usuario_id,))
        user_row = cursor.fetchone()

        if not user_row:
            print(f"API /profile Error: Usuario con ID {usuario_id} no encontrado en BD (token válido pero usuario inexistente?).")
            # Si el token es válido pero el usuario no está en BD, podría ser un 404 o un 401/403.
            # 404 es razonable aquí.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")

        nombre_usuario_db = user_row.nombre_usuario # Acceso por nombre de columna (si tu cursor lo permite) o índice [0]
        plan_id_db = user_row.plan_id # Acceso por nombre de columna o índice [1]

        # --- Mapeo de plan_id a descripción ---
        if plan_id_db == 1:
            plan_descripcion = "plan basico"
        elif plan_id_db == 2:
            plan_descripcion = "estandar"
        elif plan_id_db == 3:
            plan_descripcion = "Premium"
        else:
            plan_descripcion = "desconocido" # O manejar como error
            print(f"WARN /profile: plan_id '{plan_id_db}' no reconocido para usuario {usuario_id}.")

        print(f"API /profile: Perfil encontrado - Usuario: {nombre_usuario_db}, Plan: {plan_descripcion}")

        # Crear y devolver la respuesta usando el esquema Pydantic
        return UserProfileResponse(
            nombre_usuario=nombre_usuario_db,
            plan_descripcion=plan_descripcion
        )

    except pyodbc.Error as db_err:
        err_msg = f"SQLSTATE: {db_err.args[0]} - Mensaje: {db_err.args[1]}"
        print(f"[ERROR CRÍTICO] Error BD en /profile: {err_msg}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno al obtener perfil.")
    except Exception as e:
        print(f"[ERROR CRÍTICO] Error inesperado en /profile: {e}")
        traceback.print_exc()
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Error interno inesperado al obtener perfil.")
    finally:
        # Asegurar cierre de recursos DB
        if cursor: cursor.close()
        if conn: conn.close()
