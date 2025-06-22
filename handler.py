import boto3
import hashlib
import uuid
from datetime import datetime, timedelta
from diagrams import Diagram
from diagrams.aws.compute import EC2, Lambda
from io import BytesIO
import json
from diagrams.aws.network import VPC
from datetime import datetime

# Función 1: Crear Usuario
# Hashear contraseña
def hash_password(password):
    # Retorna la contraseña hasheada
    return hashlib.sha256(password.encode()).hexdigest()

# Función que maneja el registro de user y validación del password
def crearUsuario(event, context):
    try:
        # Obtener el email y el password
        user_id = event.get('user_id')
        password = event.get('password')
        
        # Verificar que el email y el password existen
        if user_id and password:
            # Hashea la contraseña antes de almacenarla
            hashed_password = hash_password(password)
            # Conectar DynamoDB
            dynamodb = boto3.resource('dynamodb')
            t_usuarios = dynamodb.Table('t_usuarios')
            # Almacena los datos del user en la tabla de usuarios en DynamoDB
            t_usuarios.put_item(
                Item={
                    'user_id': user_id,
                    'password': hashed_password,
                }
            )
            # Retornar un código de estado HTTP 200 (OK) y un mensaje de éxito
            mensaje = {
                'message': 'User registered successfully',
                'user_id': user_id
            }
            return {
                'statusCode': 200,
                'body': mensaje
            }
        else:
            mensaje = {
                'error': 'Invalid request body: missing user_id or password'
            }
            return {
                'statusCode': 400,
                'body': mensaje
            }

    except Exception as e:
        # Excepción y retornar un código de error HTTP 500
        print("Exception:", str(e))
        mensaje = {
            'error': str(e)
        }        
        return {
            'statusCode': 500,
            'body': mensaje
        }


# Función 2: Login de Usuario
def loginUsuario(event, context):
    # Entrada (json)
    user_id = event['user_id']
    password = event['password']
    hashed_password = hash_password(password)
    # Proceso
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('t_usuarios')
    response = table.get_item(
        Key={
            'user_id': user_id
        }
    )
    if 'Item' not in response:
        return {
            'statusCode': 403,
            'body': 'Usuario no existe'
        }
    else:
        hashed_password_bd = response['Item']['password']
        if hashed_password == hashed_password_bd:
            # Genera token
            token = str(uuid.uuid4())
            fecha_hora_exp = datetime.now() + timedelta(minutes=60)
            registro = {
                'token': token,
                'expires': fecha_hora_exp.strftime('%Y-%m-%d %H:%M:%S')
            }
            table = dynamodb.Table('t_tokens_acceso')
            dynamodbResponse = table.put_item(Item = registro)
        else:
            return {
                'statusCode': 403,
                'body': 'Password incorrecto'
            }
    
    # Salida (json)
    return {
        'statusCode': 200,
        'token': token
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

# Inicio - Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')    
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    print(response)
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }
    # Fin - Proteger el Lambda 

    diagram_code = event['body']['diagram_code']
    diagram_type = event['body'].get('diagram_type', 'aws')  # Tipo de diagrama (por defecto AWS)
    user_id = event['user_id']
    
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
            # Ejemplo: Diagrama de AWS con EC2 y Lambda
            EC2("EC2 Instance")
            Lambda("Lambda Function")
            VPC("VPC Network")
        elif diagram_type == 'er':
            # Si es un diagrama ER, podemos agregar lógica para generar un diagrama ER (con ERAlchemy)
            pass
        elif diagram_type == 'mermaid':
            # Lógica para generar diagrama con Mermaid (opcional)
            pass
        else:
            return {
                'statusCode': 400,
                'body': 'Tipo de diagrama no soportado'
            }

    # Guardar el diagrama como imagen en formato PNG
    img_stream = BytesIO()
    diag.render(img_stream, format="png")
    img_stream.seek(0)

    # Subir la imagen a S3
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

# Inicio - Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')    
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    print(response)
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }
    # Fin - Proteger el Lambda 

    diagram_code = event['body']['diagram_code']

    if not diagram_code:
        return {
            'statusCode': 400,
            'body': 'Código del diagrama vacío'
        }

    try:
        # Intentar cargar el código como JSON
        diagram_data = json.loads(diagram_code)
    except json.JSONDecodeError:
        return {
            'statusCode': 400,
            'body': 'Código del diagrama en formato incorrecto'
        }

    # Validar los datos (Ejemplo para un diagrama de AWS)
    if 'EC2' not in diagram_data:
        return {
            'statusCode': 400,
            'body': 'Falta un recurso EC2 en el diagrama'
        }

    # Si todo está bien, retornar éxito
    return {
        'statusCode': 200,
        'body': 'Diagrama válido'
    }



# Función 6: Guardar Diagrama en S3
def guardarDiagramaS3(event, context):

# Inicio - Proteger el Lambda
    token = event['headers']['Authorization']
    lambda_client = boto3.client('lambda')    
    payload_string = '{ "token": "' + token +  '" }'
    invoke_response = lambda_client.invoke(FunctionName="ValidarTokenAcceso",
                                           InvocationType='RequestResponse',
                                           Payload = payload_string)
    response = json.loads(invoke_response['Payload'].read())
    print(response)
    if response['statusCode'] == 403:
        return {
            'statusCode' : 403,
            'status' : 'Forbidden - Acceso No Autorizado'
        }
    # Fin - Proteger el Lambda 

    diagram_code = event['body']['diagram_code']
    s3_client = boto3.client('s3')
    bucket_name = event['env']['DIAGRAM_BUCKET']
    s3_key = f"diagrams/{event['user_id']}/{uuid.uuid4()}.txt"  # Usar UUID para el archivo

    # Guardar el código como archivo de texto en S3
    s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=diagram_code)

    return {
        'statusCode': 200,
        'message': 'Código del diagrama guardado en S3',
        's3_url': f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"
    }
