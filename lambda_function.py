import boto3
import datetime
import json

# Initialize Boto3 clients for CloudTrail and SES
cloudtrail_client = boto3.client('cloudtrail')
ses_client = boto3.client('ses')

# Configuration
email_sender = 'xxxx@gmail.com'  # Verified SES sender email
email_recipient = 'xxxx@gmail.com'  # Recipient email

def send_email(event_details):
    """Send email using SES when a violation is detected."""
    event_name = event_details.get('eventName', 'Unknown Event')
    event_time = event_details.get('eventTime', 'Unknown Time')
    event_id = event_details.get('eventID', 'Unknown ID')
    
    # Extract AWS Account ID and the user who made the change
    aws_account_id = event_details.get('userIdentity', {}).get('accountId', 'Unknown Account')
    user_identity = event_details.get('userIdentity', {}).get('arn', 'Unknown User')
    
    # Custom email subject and body
    subject = "Freeze Change Violation"
    body = (f"Violation detected:\n"
            f"Event Name: {event_name}\n"
            f"Event Time: {event_time}\n"
            f"Event ID: {event_id}\n"
            f"AWS Account ID: {aws_account_id}\n"
            f"User Who Made Changes: {user_identity}")
    
    print("Preparing to send email notification...")

    try:
        response = ses_client.send_email(
            Source=email_sender,
            Destination={
                'ToAddresses': [email_recipient],
            },
            Message={
                'Subject': {
                    'Data': subject,
                },
                'Body': {
                    'Text': {
                        'Data': body,
                    }
                }
            }
        )
        print("Email sent response:", response)
    except Exception as e:
        print(f"Error sending email: {e}")

def check_cloudtrail_for_violations():
    """Check CloudTrail for Create, Update, and Modify events."""
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(hours=24)
    print(f"Checking CloudTrail events from {start_time} to {end_time}...")

    try:
        # Explicitly include CreateBucket and general Create* events
        response = cloudtrail_client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'CreateBucket'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'Create*'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'Update*'
                },
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'Modify*'
                }
            ]
        )

        events = response.get('Events', [])
        if not events:
            print("No CloudTrail events detected.")
        else:
            print(f"Events detected: {events}")
            for event in events:
                event_details = json.loads(event['CloudTrailEvent'])
                print(f"Event details: {event_details}")
                send_email(event_details)
    except Exception as e:
        print(f"Error fetching CloudTrail events: {e}")

def lambda_handler(event, context):
    """AWS Lambda handler function"""
    print("Lambda function started.")
    check_cloudtrail_for_violations()
    print("Lambda function finished.")
