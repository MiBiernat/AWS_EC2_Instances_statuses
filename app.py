from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import boto3
import logging
from dotenv import load_dotenv
import os

# Configure logging
logging.basicConfig(filename='instance_log.txt', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('your-secret-key')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# Dummy user database
users = {
    'admin@example.com': {'password': 'secret'},
    'adambemowski@gmail.com': {'password': 'adambemowski@gmail.com'}
}


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email
    user.is_authenticated = request.form['password'] == users[email]['password']

    return user


@app.route('/')
def index():
    return 'Hello, World!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        if email in users and request.form['password'] == users[email]['password']:
            user = User()
            user.id = email
            login_user(user)
            return redirect(url_for('instances'))

        return 'Bad login'

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# Initialize Boto3 EC2 client
ec2 = boto3.client(
    'ec2',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)


@app.route('/instances')
@login_required
def instances():
    # List all instances
    reservations = ec2.describe_instances()['Reservations']
    instances_info = []
    for reservation in reservations:
        for instance in reservation['Instances']:
            # Get the instance name from tags
            instance_name = ''
            if 'Tags' in instance:
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
            # Append instance information including name and Public IPv4 DNS
            instances_info.append({
                'id': instance['InstanceId'],
                'state': instance['State']['Name'],
                'name': instance_name,
                'public_dns': instance.get('PublicDnsName', '')  # Add this line
            })
    return render_template('instances.html', instances=instances_info)



@app.route('/start/<instance_id>')
@login_required
def start_instance(instance_id):
    # Start an EC2 instance
    ec2.start_instances(InstanceIds=[instance_id])
    log_instance_action(user_id=current_user.id, action='START', instance_id=instance_id)
    return redirect(url_for('instances'))


@app.route('/stop/<instance_id>')
@login_required
def stop_instance(instance_id):
    # Stop an EC2 instance
    ec2.stop_instances(InstanceIds=[instance_id])
    log_instance_action(user_id=current_user.id, action='STOP', instance_id=instance_id)
    return redirect(url_for('instances'))


def log_instance_action(user_id, action, instance_id):
    logging.info(
        f"User: {user_id}, Action: {action}, Instance ID: {instance_id}, Timestamp: {datetime.now().isoformat()}")


if __name__ == '__main__':
    app.run(debug=True)
