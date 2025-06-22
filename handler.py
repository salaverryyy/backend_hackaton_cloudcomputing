import boto3
import hashlib
import uuid
from datetime import datetime, timedelta
import json

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
def generarDiagrama(event, context):
    from diagrams import Diagram
    from diagrams.aws.compute import EC2, Lambda
    from diagrams.aws.network import VPC
    from io import BytesIO

    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    elif isinstance(raw_body, dict):
        payload = raw_body
    else:
        payload = event

    diagram_code = payload.get('diagram_code')
    diagram_type = payload.get('diagram_type', 'aws')
    user_id = payload.get('user_id')

    if not diagram_code:
        return {
            'statusCode': 400,
            'body': 'Código de diagrama no proporcionado'
        }

    # Decodificar el código del diagrama si está en formato JSON
    try:
        diagram_data = json.loads(diagram_code)
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': 'Código de diagrama en formato incorrecto'
        }

    # Generar el diagrama
    with Diagram(f"AWS Diagram for {user_id}", show=False) as diag:
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
                'body': 'Tipo de diagrama no soportado'
            }

    img_stream = BytesIO()
    diag.render(img_stream, format="png")
    img_stream.seek(0)

    s3_client = boto3.client('s3')
    bucket_name = event['env']['DIAGRAM_BUCKET']
    s3_key = f"diagrams/{user_id}/{uuid.uuid4()}.png"

    s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=img_stream)

    return {
        'statusCode': 200,
        'message': 'Diagrama generado y guardado en S3',
        's3_url': f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"
    }


# Función 5: Validar Diagrama
def validarDiagrama(event, context):
    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')    
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    elif isinstance(raw_body, dict):
        payload = raw_body
    else:
        payload = event

    diagram_code = payload.get('diagram_code')

    if not diagram_code:
        return {
            'statusCode': 400,
            'body': 'Código del diagrama vacío'
        }

    try:
        diagram_data = json.loads(diagram_code)
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': 'Código del diagrama en formato incorrecto'
        }

    if 'EC2' not in diagram_data:
        return {
            'statusCode': 400,
            'body': 'Falta un recurso EC2 en el diagrama'
        }

    return {
        'statusCode': 200,
        'body': 'Diagrama válido'
    }

# Función 6: Guardar Diagrama en S3
def guardarDiagramaS3(event, context):
    # Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }

    # EXTRAER EL BODY CORRECTAMENTE
    raw_body = event.get('body')
    if isinstance(raw_body, str):
        payload = json.loads(raw_body)
    elif isinstance(raw_body, dict):
        payload = raw_body
    else:
        payload = event

    diagram_code = payload.get('diagram_code')
    user_id = payload.get('user_id')

    s3_client = boto3.client('s3')
    bucket_name = event['env']['DIAGRAM_BUCKET']
    s3_key = f"diagrams/{user_id}/{uuid.uuid4()}.txt"

    s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=diagram_code)

    return {
        'statusCode': 200,
        'message': 'Código del diagrama guardado en S3',
        's3_url': f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"
    }
