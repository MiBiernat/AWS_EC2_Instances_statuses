import json
import logging
import os
from datetime import datetime

import boto3
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from starlette.responses import RedirectResponse

# Configure logging
logging.basicConfig(filename='instance_log.txt', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

load_dotenv()

app = FastAPI()
security = HTTPBasic()

# Load user data
with open('users.json') as f:
    users = json.load(f)


# User model for response
class User(BaseModel):
    email: str


# Initialize Boto3 EC2 client
ec2 = boto3.client(
    'ec2',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)


# Helper function for authentication
def authenticate_user(credentials: HTTPBasicCredentials):
    email = credentials.username
    password = credentials.password

    if email in users and password == users[email]['password']:
        return User(email=email)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/")
def read_root():
    return {"message": "Hello, World!"}


@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    return user


@app.get("/instances", response_model=list)
def list_instances(credentials: HTTPBasicCredentials = Depends(security)):
    _ = authenticate_user(credentials)  # Authenticate user

    reservations = ec2.describe_instances()['Reservations']
    instances_info = []
    for reservation in reservations:
        for instance in reservation['Instances']:
            instance_name = ''
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
            instances_info.append({
                'id': instance['InstanceId'],
                'state': instance['State']['Name'],
                'name': instance_name,
                'public_dns': instance.get('PublicDnsName', '')
            })
    return instances_info


@app.post("/start/{instance_id}")
def start_instance(instance_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    ec2.start_instances(InstanceIds=[instance_id])
    log_instance_action(user_id=user.email, action='START', instance_id=instance_id)
    return {"message": "Instance started"}


@app.post("/stop/{instance_id}")
def stop_instance(instance_id: str, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate_user(credentials)
    ec2.stop_instances(InstanceIds=[instance_id])
    log_instance_action(user_id=user.email, action='STOP', instance_id=instance_id)
    return {"message": "Instance stopped"}


def log_instance_action(user_id, action, instance_id):
    logging.info(
        f"User: {user_id}, Action: {action}, Instance ID: {instance_id}, Timestamp: {datetime.now().isoformat()}")

    # To run the server, use "uvicorn filename:app --reload"
    f"User: {user_id}, Action: {action}, Instance ID: {instance_id}, Timestamp: {datetime.now().isoformat()}"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8081)
