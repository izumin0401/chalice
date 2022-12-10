from chalice import Chalice, IAMAuthorizer
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
import boto3
import json
import requests

app = Chalice(app_name='hello-world')

authorizer = IAMAuthorizer()

@app.route('/authorizer', methods=['GET'], authorizer=authorizer)
def index():
    return {'hello': 'world'}

@app.route('/exec-authorizer', methods=['GET'])
def exec_authorizer():
    REGION = 'ap-northeast-1'
    ARN_ID_POOL = 'ap-northeast-1:XXXXX'

    client = boto3.client('cognito-identity', REGION)

    credentials_for_identity = client.get_credentials_for_identity(
        IdentityId=client.get_id(IdentityPoolId=ARN_ID_POOL)['IdentityId']
    )

    session = boto3.session.Session(
        aws_access_key_id=credentials_for_identity['Credentials']['AccessKeyId'],
        aws_secret_access_key=credentials_for_identity['Credentials']['SecretKey'],
        aws_session_token=credentials_for_identity['Credentials']['SessionToken'],
        region_name=REGION
    )

    url = 'https://XXXXX.execute-api.ap-northeast-1.amazonaws.com/api/authorizer/'

    credentials = session.get_credentials()
    request = AWSRequest(method = "GET", url = url)
    SigV4Auth(credentials, 'execute-api', REGION).add_auth(request)

    res = requests.get(
        url,
        headers = {
            'Authorization': request.headers['Authorization'],
            'X-Amz-Date': request.context['timestamp'],
            'X-Amz-Security-Token': credentials_for_identity['Credentials']['SessionToken']
        }
    )

    return res.json()
