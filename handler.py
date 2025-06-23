import boto3
import hashlib
import sys
import os
import uuid
from datetime import datetime, timedelta
import json


os.environ["PATH"] = os.path.join(os.getcwd(), "bin") + os.pathsep + os.environ.get("PATH", "")
sys.path.append(os.getcwd())
# Función 1: Crear Usuario
# Hashear contraseña
def hash_password(password):
    # Retorna la contraseña hasheada
    return hashlib.sha256(password.encode()).hexdigest()

# Función que maneja el registro de user y validación del password
def crearUsuario(event, context):
    try:
        raw_body = event.get('body')
        if isinstance(raw_body, str):
            payload = json.loads(raw_body)
        elif isinstance(raw_body, dict):
            payload = raw_body
        else:
            payload = event

        user_id = payload.get('user_id')
        password = payload.get('password')

        if not user_id or not password:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Faltan user_id o password'})
            }

        # 4) Hashear y guardar en DynamoDB
        hashed = hash_password(password)
        dynamodb = boto3.resource('dynamodb')
        tabla = dynamodb.Table('t_usuarios')
        tabla.put_item(Item={
            'user_id': user_id,
            'password': hashed
        })

        # 5) Responder éxito
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Usuario registrado con éxito',
                'user_id': user_id
            })
        }

    except Exception as e:
        print("Error al crear usuario:", e)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error interno del servidor'})
        }

# Función 2: Login de Usuario
def loginUsuario(event, context):
    # 1) Parsear el payload: str → loads, dict → usar directo
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    elif isinstance(raw_body, dict):
        payload = raw_body
    else:
        # Por si invocas localmente sin proxy
        payload = event

    # 2) Extraer campos
    user_id = payload.get('user_id')
    password = payload.get('password')

    # 3) Validación básica
    if not user_id or not password:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Faltan user_id o password'})
        }

    # 4) Comprobar en DynamoDB
    hashed_password = hash_password(password)
    dynamodb = boto3.resource('dynamodb')
    usuarios_tabla = dynamodb.Table('t_usuarios')
    resp = usuarios_tabla.get_item(Key={'user_id': user_id})

    if 'Item' not in resp:
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Usuario no existe'})
        }

    if resp['Item']['password'] != hashed_password:
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Password incorrecto'})
        }

    # 5) Generar token
    token = str(uuid.uuid4())
    expires = (datetime.now() + timedelta(minutes=60)).strftime('%Y-%m-%d %H:%M:%S')
    tokens_tabla = dynamodb.Table('t_tokens_acceso')
    tokens_tabla.put_item(Item={
        'token': token,
        'expires': expires
    })

    # 6) Devolver token
    return {
        'statusCode': 200,
        'body': json.dumps({'token': token})
    }

# Función 3: Validar Token de Acceso
def validarTokenAcceso(event, context):
    # Entrada (json)
    token = event['token']
    # Proceso
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('t_tokens_acceso')
    response = table.get_item(
        Key={
            'token': token
        }
    )
    if 'Item' not in response:
        return {
            'statusCode': 403,
            'body': 'Token no existe'
        }
    else:
        expires = response['Item']['expires']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if now > expires:
            return {
                'statusCode': 403,
                'body': 'Token expirado'
            }

    # Salida (json)
    return {
        'statusCode': 200,
        'body': 'Token válido'
    }


# Función 4: Generar Diagrama
# Función 4: Generar Diagrama
def generarDiagrama(event, context):
    from diagrams import Diagram
    from diagrams.aws.compute import EC2, Lambda
    from diagrams.aws.network import VPC
    
    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')
    payload_string = json.dumps({ "token": token })
    invoke_response = lambda_client.invoke(FunctionName="validarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response.get('statusCode') != 200:
        return {
            'statusCode' : 403,
            'body' : json.dumps({'error': 'Forbidden - Acceso No Autorizado'})
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    else:
        payload = raw_body

    diagram_code = payload.get('diagram_code')
    diagram_type = payload.get('diagram_type', 'aws')
    user_id = payload.get('user_id')

    if not diagram_code:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Código de diagrama no proporcionado'})
        }

    # Decodificar el código del diagrama si está en formato JSON
    try:
        json.loads(diagram_code)
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Código de diagrama en formato incorrecto'})
        }

    # --- CAMBIO CLAVE: usar /tmp/ ---
    # La librería añade la extensión .png automáticamente al nombre de archivo
    output_filename = f"/tmp/aws_diagram_for_{user_id}"

    # Generar el diagrama en /tmp/
    with Diagram(f"AWS Diagram for {user_id}", show=False, filename=output_filename, outformat="png") as diag:
        if diagram_type == 'aws':
            EC2("EC2 Instance")
            Lambda("Lambda Function")
            VPC("VPC Network")
        elif diagram_type == 'er':
            pass
        elif diagram_type == 'mermaid':
            pass
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Tipo de diagrama no soportado'})
            }

    # --- CAMBIO CLAVE: Leer el archivo desde /tmp para subirlo a S3 ---
    s3_client = boto3.client('s3')
    bucket_name = os.environ.get('DIAGRAM_BUCKET')
    s3_key = f"diagrams/{user_id}/{uuid.uuid4()}.png"

    try:
        # El nombre completo del archivo generado es output_filename + ".png"
        with open(f"{output_filename}.png", "rb") as f:
            s3_client.upload_fileobj(f, bucket_name, s3_key)
    except FileNotFoundError:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'No se pudo generar el archivo del diagrama en /tmp'})
        }
    
    s3_url = f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Diagrama generado y guardado en S3',
            's3_url': s3_url
        })
    }


# Función 5: Validar Diagrama
# Función 5: Validar Diagrama
def validarDiagrama(event, context):
    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')    
    payload_string = json.dumps({ "token": token })
    invoke_response = lambda_client.invoke(FunctionName="validarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response.get('statusCode') != 200:
        return {
            'statusCode' : 403,
            'body' : json.dumps({'error': 'Forbidden - Acceso No Autorizado'})
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    else:
        payload = raw_body

    diagram_code = payload.get('diagram_code')

    if not diagram_code:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Código del diagrama vacío'})
        }

    try:
        diagram_data = json.loads(diagram_code)
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Código del diagrama en formato incorrecto'})
        }

    if 'EC2' not in diagram_data:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Falta un recurso EC2 en el diagrama'})
        }

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Diagrama válido'})
    }

# Función 6: Guardar Diagrama en S3
# Función 6: Guardar Diagrama en S3
def guardarDiagramaS3(event, context):
    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')
    payload_string = json.dumps({ "token": token })
    invoke_response = lambda_client.invoke(FunctionName="validarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response.get('statusCode') != 200:
        return {
            'statusCode' : 403,
            'body' : json.dumps({'error': 'Forbidden - Acceso No Autorizado'})
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    else:
        payload = raw_body

    diagram_code = payload.get('diagram_code')
    user_id = payload.get('user_id')
    
    if not diagram_code or not user_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Faltan diagram_code o user_id'})}

    s3_client = boto3.client('s3')
    bucket_name = os.environ.get('DIAGRAM_BUCKET')
    s3_key = f"diagrams/{user_id}/{uuid.uuid4()}.txt"

    s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=diagram_code)
    
    s3_url = f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Código del diagrama guardado en S3',
            's3_url': s3_url
        })
    }
