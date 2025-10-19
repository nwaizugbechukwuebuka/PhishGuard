# PhishGuard Enterprise Integrations Guide

## Overview

PhishGuard offers comprehensive integration capabilities with major email platforms, security tools, and enterprise systems. This guide provides detailed implementation instructions, configuration examples, and best practices for integrating PhishGuard into your existing security infrastructure.

## Email Platform Integrations

### Gmail API Integration

#### Prerequisites
- Google Cloud Platform project with Gmail API enabled
- Service account credentials with appropriate permissions
- Domain-wide delegation configured (for G Suite/Google Workspace)

#### Configuration

```python
# Gmail API Configuration
GMAIL_CONFIG = {
    'credentials_file': 'path/to/service-account-credentials.json',
    'scopes': [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/gmail.labels'
    ],
    'delegate_email': 'admin@yourdomain.com',
    'batch_size': 100,
    'rate_limit': 250  # requests per user per second
}
```

#### Implementation Example

```python
from google.oauth2 import service_account
from googleapiclient.discovery import build
import asyncio
from typing import List, Dict, Any

class GmailIntegration:
    def __init__(self, config: dict):
        self.config = config
        self.credentials = service_account.Credentials.from_service_account_file(
            config['credentials_file'],
            scopes=config['scopes']
        )
        self.service = None
    
    async def initialize(self):
        """Initialize Gmail API service"""
        self.service = build('gmail', 'v1', credentials=self.credentials)
        
    async def scan_mailboxes(self, user_emails: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple user mailboxes for threats"""
        results = []
        
        for user_email in user_emails:
            try:
                # Delegate credentials for user
                delegated_credentials = self.credentials.with_subject(user_email)
                user_service = build('gmail', 'v1', credentials=delegated_credentials)
                
                # Get recent emails
                messages = await self._get_recent_messages(user_service, user_email)
                
                # Process each message
                for message in messages:
                    email_data = await self._extract_email_data(user_service, message['id'])
                    threat_analysis = await self._analyze_email_threat(email_data)
                    
                    if threat_analysis['is_threat']:
                        await self._quarantine_email(user_service, message['id'])
                        results.append({
                            'user': user_email,
                            'message_id': message['id'],
                            'threat_type': threat_analysis['threat_type'],
                            'risk_score': threat_analysis['risk_score']
                        })
            
            except Exception as e:
                logger.error(f"Error scanning mailbox {user_email}: {str(e)}")
                
        return results
    
    async def _quarantine_email(self, service, message_id: str):
        """Move email to quarantine label"""
        try:
            # Create quarantine label if it doesn't exist
            quarantine_label_id = await self._ensure_quarantine_label(service)
            
            # Add quarantine label and remove from inbox
            service.users().messages().modify(
                userId='me',
                id=message_id,
                body={
                    'addLabelIds': [quarantine_label_id],
                    'removeLabelIds': ['INBOX']
                }
            ).execute()
            
        except Exception as e:
            logger.error(f"Error quarantining email {message_id}: {str(e)}")
```

#### Webhook Configuration

```python
@app.route('/webhooks/gmail', methods=['POST'])
async def gmail_webhook():
    """Handle Gmail push notifications"""
    try:
        # Verify webhook authenticity
        if not verify_gmail_webhook(request):
            return abort(401)
        
        # Parse notification
        notification = request.get_json()
        
        # Process new email
        if notification.get('emailAddress'):
            await process_gmail_notification(notification)
        
        return {'status': 'success'}, 200
    
    except Exception as e:
        logger.error(f"Gmail webhook error: {str(e)}")
        return {'error': 'Processing failed'}, 500

async def setup_gmail_push_notifications():
    """Setup Gmail push notifications via Cloud Pub/Sub"""
    topic_name = 'projects/your-project/topics/gmail-notifications'
    
    # Configure watch request
    watch_request = {
        'topicName': topic_name,
        'labelIds': ['INBOX'],
        'labelFilterAction': 'include'
    }
    
    # Set up watch for each user
    for user_email in get_monitored_users():
        service = get_gmail_service_for_user(user_email)
        service.users().watch(userId='me', body=watch_request).execute()
```

### Microsoft 365 Integration

#### Prerequisites
- Azure AD application registration
- Microsoft Graph API permissions
- Administrative consent for organization-wide access

#### Configuration

```python
# Microsoft 365 Configuration
M365_CONFIG = {
    'client_id': 'your-azure-app-client-id',
    'client_secret': 'your-azure-app-secret',
    'tenant_id': 'your-azure-tenant-id',
    'scopes': [
        'https://graph.microsoft.com/Mail.Read',
        'https://graph.microsoft.com/Mail.ReadWrite',
        'https://graph.microsoft.com/User.Read.All'
    ],
    'authority': 'https://login.microsoftonline.com',
    'batch_size': 100
}
```

#### Implementation Example

```python
import msal
from msgraph.core import GraphClient
import asyncio

class Microsoft365Integration:
    def __init__(self, config: dict):
        self.config = config
        self.app = msal.ConfidentialClientApplication(
            config['client_id'],
            authority=f"{config['authority']}/{config['tenant_id']}",
            client_credential=config['client_secret']
        )
        self.graph_client = None
    
    async def initialize(self):
        """Initialize Microsoft Graph client"""
        # Get access token
        token_response = self.app.acquire_token_for_client(
            scopes=['https://graph.microsoft.com/.default']
        )
        
        if 'access_token' in token_response:
            self.graph_client = GraphClient(credential=token_response['access_token'])
        else:
            raise Exception("Failed to acquire access token")
    
    async def scan_exchange_mailboxes(self) -> List[Dict[str, Any]]:
        """Scan Exchange Online mailboxes for threats"""
        results = []
        
        # Get all users
        users_response = await self.graph_client.get('/users')
        users = users_response.json().get('value', [])
        
        for user in users:
            user_id = user['id']
            user_email = user['mail'] or user['userPrincipalName']
            
            try:
                # Get user's messages
                messages_response = await self.graph_client.get(
                    f'/users/{user_id}/messages',
                    params={
                        '$top': 50,
                        '$filter': 'receivedDateTime ge ' + 
                                 (datetime.utcnow() - timedelta(hours=24)).isoformat() + 'Z'
                    }
                )
                
                messages = messages_response.json().get('value', [])
                
                for message in messages:
                    email_data = await self._convert_message_to_email_data(message)
                    threat_analysis = await self._analyze_email_threat(email_data)
                    
                    if threat_analysis['is_threat']:
                        await self._quarantine_exchange_email(user_id, message['id'])
                        results.append({
                            'user': user_email,
                            'message_id': message['id'],
                            'threat_type': threat_analysis['threat_type'],
                            'risk_score': threat_analysis['risk_score']
                        })
            
            except Exception as e:
                logger.error(f"Error scanning mailbox {user_email}: {str(e)}")
        
        return results
    
    async def _quarantine_exchange_email(self, user_id: str, message_id: str):
        """Move email to quarantine folder"""
        try:
            # Get or create quarantine folder
            quarantine_folder_id = await self._ensure_quarantine_folder(user_id)
            
            # Move message to quarantine folder
            await self.graph_client.post(
                f'/users/{user_id}/messages/{message_id}/move',
                json={'destinationId': quarantine_folder_id}
            )
            
        except Exception as e:
            logger.error(f"Error quarantining email {message_id}: {str(e)}")
```

#### Graph API Webhook Setup

```python
async def setup_m365_subscriptions():
    """Setup Microsoft Graph webhooks for real-time email monitoring"""
    
    subscription_request = {
        'changeType': 'created',
        'notificationUrl': 'https://your-domain.com/webhooks/m365',
        'resource': '/users/{user-id}/messages',
        'expirationDateTime': (datetime.utcnow() + timedelta(days=3)).isoformat() + 'Z',
        'clientState': 'your-secret-state'
    }
    
    # Create subscription for each monitored user
    for user_id in get_monitored_user_ids():
        subscription_request['resource'] = f'/users/{user_id}/messages'
        
        response = await graph_client.post('/subscriptions', json=subscription_request)
        
        if response.status_code == 201:
            subscription_data = response.json()
            await store_subscription_data(user_id, subscription_data)

@app.route('/webhooks/m365', methods=['POST'])
async def m365_webhook():
    """Handle Microsoft 365 webhook notifications"""
    try:
        # Validate webhook
        if not validate_m365_webhook(request):
            return abort(401)
        
        # Process notification
        notifications = request.get_json().get('value', [])
        
        for notification in notifications:
            if notification.get('changeType') == 'created':
                await process_m365_email_notification(notification)
        
        return {'status': 'success'}, 200
    
    except Exception as e:
        logger.error(f"M365 webhook error: {str(e)}")
        return {'error': 'Processing failed'}, 500
```

## Security Tool Integrations

### SIEM Integration (Splunk, QRadar, Sentinel)

#### Splunk Integration

```python
class SplunkIntegration:
    def __init__(self, config: dict):
        self.splunk_host = config['host']
        self.splunk_port = config['port']
        self.username = config['username']
        self.password = config['password']
        self.service = None
    
    async def initialize(self):
        """Initialize Splunk connection"""
        try:
            self.service = client.connect(
                host=self.splunk_host,
                port=self.splunk_port,
                username=self.username,
                password=self.password
            )
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {str(e)}")
            raise
    
    async def send_threat_event(self, threat_data: dict):
        """Send threat detection event to Splunk"""
        try:
            # Format event for Splunk
            splunk_event = {
                'time': threat_data['timestamp'],
                'source': 'phishguard',
                'sourcetype': 'phishguard:threat',
                'index': 'security',
                'event': {
                    'threat_id': threat_data['threat_id'],
                    'email_sender': threat_data['sender'],
                    'email_recipient': threat_data['recipient'],
                    'threat_type': threat_data['threat_type'],
                    'risk_score': threat_data['risk_score'],
                    'action_taken': threat_data['action'],
                    'indicators': threat_data['indicators']
                }
            }
            
            # Send to Splunk HTTP Event Collector
            await self._send_to_hec(splunk_event)
            
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {str(e)}")
    
    async def query_threat_intelligence(self, ioc: str) -> dict:
        """Query Splunk for threat intelligence"""
        search_query = f'''
        search index=threat_intelligence 
        | where ioc="{ioc}" 
        | stats latest(threat_type) as threat_type, 
                latest(confidence) as confidence,
                latest(last_seen) as last_seen
        '''
        
        try:
            job = self.service.jobs.create(search_query)
            
            # Wait for job completion
            while not job.is_done():
                await asyncio.sleep(1)
            
            # Get results
            results = job.results()
            return self._parse_threat_intel_results(results)
            
        except Exception as e:
            logger.error(f"Splunk query failed: {str(e)}")
            return {}
```

#### IBM QRadar Integration

```python
class QRadarIntegration:
    def __init__(self, config: dict):
        self.qradar_host = config['host']
        self.api_token = config['api_token']
        self.session = aiohttp.ClientSession(
            headers={'SEC': self.api_token}
        )
    
    async def send_offense_data(self, threat_data: dict):
        """Send threat data as QRadar offense"""
        try:
            offense_data = {
                'description': f"PhishGuard Threat Detection: {threat_data['threat_type']}",
                'assigned_to': 'security_team',
                'status': 'OPEN',
                'magnitude': self._calculate_magnitude(threat_data['risk_score']),
                'categories': ['Email Security', 'Phishing'],
                'source_addresses': [threat_data.get('source_ip', 'unknown')],
                'destination_addresses': [threat_data.get('dest_ip', 'unknown')]
            }
            
            async with self.session.post(
                f'https://{self.qradar_host}/api/siem/offenses',
                json=offense_data
            ) as response:
                if response.status == 201:
                    offense = await response.json()
                    logger.info(f"Created QRadar offense: {offense['id']}")
                    return offense['id']
                
        except Exception as e:
            logger.error(f"QRadar offense creation failed: {str(e)}")
    
    async def enrich_with_threat_data(self, email_data: dict) -> dict:
        """Enrich email analysis with QRadar threat intelligence"""
        try:
            # Query for similar threats
            ariel_query = f'''
            SELECT sourceip, destinationip, eventname, magnitude
            FROM events 
            WHERE eventname LIKE '%phish%' 
            AND starttime > '{(datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")}'
            '''
            
            async with self.session.post(
                f'https://{self.qradar_host}/api/ariel/searches',
                json={'query_expression': ariel_query}
            ) as response:
                search_data = await response.json()
                search_id = search_data['search_id']
            
            # Wait for search completion and get results
            results = await self._wait_for_search_results(search_id)
            return self._analyze_threat_patterns(results)
            
        except Exception as e:
            logger.error(f"QRadar enrichment failed: {str(e)}")
            return {}
```

### SOAR Integration (Phantom, Demisto)

#### Phantom Integration

```python
class PhantomIntegration:
    def __init__(self, config: dict):
        self.phantom_host = config['host']
        self.auth_token = config['auth_token']
        self.session = aiohttp.ClientSession(
            headers={'ph-auth-token': self.auth_token}
        )
    
    async def create_incident_container(self, threat_data: dict) -> int:
        """Create incident container in Phantom"""
        try:
            container_data = {
                'name': f"PhishGuard Threat: {threat_data['threat_id']}",
                'description': f"Threat detected in email from {threat_data['sender']}",
                'label': 'phishing',
                'severity': self._map_severity(threat_data['risk_score']),
                'sensitivity': 'amber',
                'status': 'new',
                'source_data_identifier': threat_data['email_id']
            }
            
            async with self.session.post(
                f'https://{self.phantom_host}/rest/container',
                json=container_data
            ) as response:
                if response.status == 200:
                    container = await response.json()
                    container_id = container['id']
                    
                    # Add artifacts
                    await self._add_artifacts(container_id, threat_data)
                    
                    # Trigger playbook
                    await self._trigger_playbook(container_id, 'phishing_response')
                    
                    return container_id
                
        except Exception as e:
            logger.error(f"Phantom container creation failed: {str(e)}")
            return None
    
    async def _add_artifacts(self, container_id: int, threat_data: dict):
        """Add artifacts to Phantom container"""
        artifacts = [
            {
                'container_id': container_id,
                'name': 'Email Sender',
                'label': 'sender',
                'type': 'email',
                'value': threat_data['sender'],
                'source_data_identifier': 'sender_address'
            },
            {
                'container_id': container_id,
                'name': 'Email Subject',
                'label': 'subject',
                'type': 'email subject',
                'value': threat_data['subject'],
                'source_data_identifier': 'email_subject'
            }
        ]
        
        # Add URL artifacts if present
        for url in threat_data.get('urls', []):
            artifacts.append({
                'container_id': container_id,
                'name': 'Suspicious URL',
                'label': 'url',
                'type': 'url',
                'value': url,
                'source_data_identifier': f'url_{len(artifacts)}'
            })
        
        # Batch create artifacts
        async with self.session.post(
            f'https://{self.phantom_host}/rest/artifact',
            json=artifacts
        ) as response:
            if response.status != 200:
                logger.error(f"Failed to create artifacts: {response.status}")
```

## Collaboration Platform Integrations

### Slack Integration

#### Configuration

```python
SLACK_CONFIG = {
    'bot_token': 'xoxb-your-bot-token',
    'signing_secret': 'your-signing-secret',
    'channels': {
        'alerts': '#security-alerts',
        'incidents': '#security-incidents',
        'reports': '#security-reports'
    },
    'webhook_url': 'https://hooks.slack.com/services/...'
}
```

#### Implementation

```python
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.signature import SignatureVerifier

class SlackIntegration:
    def __init__(self, config: dict):
        self.client = AsyncWebClient(token=config['bot_token'])
        self.signing_secret = config['signing_secret']
        self.channels = config['channels']
        self.signature_verifier = SignatureVerifier(self.signing_secret)
    
    async def send_threat_alert(self, threat_data: dict):
        """Send threat alert to Slack channel"""
        try:
            # Create rich message with blocks
            blocks = self._create_threat_alert_blocks(threat_data)
            
            # Send to alerts channel
            response = await self.client.chat_postMessage(
                channel=self.channels['alerts'],
                text=f"🚨 Threat Detected: {threat_data['threat_type']}",
                blocks=blocks
            )
            
            # Create thread with additional details
            await self._send_threat_details_thread(
                response['channel'], 
                response['ts'], 
                threat_data
            )
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")
    
    def _create_threat_alert_blocks(self, threat_data: dict) -> list:
        """Create Slack blocks for threat alert"""
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢'
        }
        
        severity = self._calculate_severity(threat_data['risk_score'])
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji[severity]} PhishGuard Threat Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat Type:* {threat_data['threat_type']}"
                    },
                    {
                        "type": "mrkdwn", 
                        "text": f"*Risk Score:* {threat_data['risk_score']}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Sender:* {threat_data['sender']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Recipient:* {threat_data['recipient']}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Subject:* {threat_data['subject']}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Details"},
                        "style": "primary",
                        "url": f"https://phishguard.company.com/threats/{threat_data['threat_id']}"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Quarantine"},
                        "style": "danger",
                        "value": f"quarantine_{threat_data['threat_id']}"
                    }
                ]
            }
        ]
        
        return blocks
```

#### Interactive Slack Commands

```python
@app.route('/slack/commands', methods=['POST'])
async def handle_slack_commands():
    """Handle Slack slash commands"""
    try:
        # Verify request signature
        if not signature_verifier.is_valid_request(request.get_data(), request.headers):
            return abort(401)
        
        form_data = request.form
        command = form_data.get('command')
        text = form_data.get('text', '')
        user_id = form_data.get('user_id')
        
        if command == '/phishguard-status':
            return await handle_status_command(user_id)
        elif command == '/phishguard-search':
            return await handle_search_command(text, user_id)
        elif command == '/phishguard-quarantine':
            return await handle_quarantine_command(text, user_id)
        
    except Exception as e:
        logger.error(f"Slack command error: {str(e)}")
        return {'text': 'Command processing failed'}, 500

async def handle_status_command(user_id: str) -> dict:
    """Handle /phishguard-status command"""
    try:
        # Get current system status
        status = await get_system_status()
        
        response = {
            'response_type': 'ephemeral',
            'text': f"PhishGuard System Status",
            'attachments': [
                {
                    'color': 'good' if status['healthy'] else 'danger',
                    'fields': [
                        {'title': 'System Health', 'value': '✅ Healthy' if status['healthy'] else '❌ Issues', 'short': True},
                        {'title': 'Emails Processed (24h)', 'value': str(status['emails_processed']), 'short': True},
                        {'title': 'Threats Detected (24h)', 'value': str(status['threats_detected']), 'short': True},
                        {'title': 'Detection Accuracy', 'value': f"{status['accuracy']:.1f}%", 'short': True}
                    ]
                }
            ]
        }
        
        return response
        
    except Exception as e:
        return {'text': f'Status check failed: {str(e)}'}
```

### Microsoft Teams Integration

```python
class TeamsIntegration:
    def __init__(self, config: dict):
        self.webhook_url = config['webhook_url']
        self.bot_app_id = config['bot_app_id']
        self.bot_password = config['bot_password']
    
    async def send_adaptive_card(self, threat_data: dict):
        """Send adaptive card to Teams channel"""
        try:
            card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.3",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "🛡️ PhishGuard Threat Alert",
                        "weight": "Bolder",
                        "size": "Medium",
                        "color": "Attention"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Threat Type", "value": threat_data['threat_type']},
                            {"title": "Risk Score", "value": f"{threat_data['risk_score']}/100"},
                            {"title": "Sender", "value": threat_data['sender']},
                            {"title": "Recipient", "value": threat_data['recipient']},
                            {"title": "Subject", "value": threat_data['subject'][:50] + '...'}
                        ]
                    }
                ],
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "View Details",
                        "url": f"https://phishguard.company.com/threats/{threat_data['threat_id']}"
                    },
                    {
                        "type": "Action.Submit",
                        "title": "Quarantine Email",
                        "data": {
                            "action": "quarantine",
                            "threat_id": threat_data['threat_id']
                        }
                    }
                ]
            }
            
            message = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=message) as response:
                    if response.status != 200:
                        logger.error(f"Teams webhook failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Teams integration error: {str(e)}")
```

## Configuration Management

### Integration Configuration Template

```yaml
# PhishGuard Integrations Configuration
integrations:
  email_platforms:
    gmail:
      enabled: true
      credentials_file: "/etc/phishguard/gmail-credentials.json"
      scopes:
        - "https://www.googleapis.com/auth/gmail.readonly"
        - "https://www.googleapis.com/auth/gmail.modify"
      batch_size: 100
      rate_limit: 250
      
    microsoft365:
      enabled: true
      client_id: "${M365_CLIENT_ID}"
      client_secret: "${M365_CLIENT_SECRET}"
      tenant_id: "${M365_TENANT_ID}"
      batch_size: 100
      
  security_tools:
    splunk:
      enabled: true
      host: "splunk.company.com"
      port: 8089
      username: "${SPLUNK_USERNAME}"
      password: "${SPLUNK_PASSWORD}"
      hec_token: "${SPLUNK_HEC_TOKEN}"
      index: "security"
      
    qradar:
      enabled: false
      host: "qradar.company.com"
      api_token: "${QRADAR_API_TOKEN}"
      
    phantom:
      enabled: false
      host: "phantom.company.com"
      auth_token: "${PHANTOM_AUTH_TOKEN}"
      
  collaboration:
    slack:
      enabled: true
      bot_token: "${SLACK_BOT_TOKEN}"
      signing_secret: "${SLACK_SIGNING_SECRET}"
      channels:
        alerts: "#security-alerts"
        incidents: "#security-incidents"
      
    teams:
      enabled: false
      webhook_url: "${TEAMS_WEBHOOK_URL}"
      
  notification:
    email_smtp:
      enabled: true
      host: "smtp.company.com"
      port: 587
      username: "${SMTP_USERNAME}"
      password: "${SMTP_PASSWORD}"
      
    sms:
      enabled: false
      provider: "twilio"
      account_sid: "${TWILIO_SID}"
      auth_token: "${TWILIO_TOKEN}"
```

### Dynamic Integration Loading

```python
class IntegrationManager:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.integrations = {}
        self.initialized = False
    
    async def initialize_integrations(self):
        """Initialize all enabled integrations"""
        try:
            # Email platforms
            if self.config['integrations']['email_platforms']['gmail']['enabled']:
                self.integrations['gmail'] = GmailIntegration(
                    self.config['integrations']['email_platforms']['gmail']
                )
                await self.integrations['gmail'].initialize()
            
            if self.config['integrations']['email_platforms']['microsoft365']['enabled']:
                self.integrations['microsoft365'] = Microsoft365Integration(
                    self.config['integrations']['email_platforms']['microsoft365']
                )
                await self.integrations['microsoft365'].initialize()
            
            # Security tools
            if self.config['integrations']['security_tools']['splunk']['enabled']:
                self.integrations['splunk'] = SplunkIntegration(
                    self.config['integrations']['security_tools']['splunk']
                )
                await self.integrations['splunk'].initialize()
            
            # Collaboration platforms
            if self.config['integrations']['collaboration']['slack']['enabled']:
                self.integrations['slack'] = SlackIntegration(
                    self.config['integrations']['collaboration']['slack']
                )
            
            self.initialized = True
            logger.info(f"Initialized {len(self.integrations)} integrations")
            
        except Exception as e:
            logger.error(f"Integration initialization failed: {str(e)}")
            raise
    
    async def broadcast_threat_alert(self, threat_data: dict):
        """Broadcast threat alert to all configured platforms"""
        tasks = []
        
        if 'slack' in self.integrations:
            tasks.append(self.integrations['slack'].send_threat_alert(threat_data))
        
        if 'teams' in self.integrations:
            tasks.append(self.integrations['teams'].send_adaptive_card(threat_data))
        
        if 'splunk' in self.integrations:
            tasks.append(self.integrations['splunk'].send_threat_event(threat_data))
        
        # Execute all notifications in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Log any failures
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Integration {i} failed: {str(result)}")
```

## Testing Integration Endpoints

### Integration Health Checks

```python
@router.get("/integrations/health")
async def check_integration_health():
    """Check health of all integrations"""
    health_status = {}
    
    for name, integration in integration_manager.integrations.items():
        try:
            if hasattr(integration, 'health_check'):
                status = await integration.health_check()
            else:
                status = {'status': 'unknown', 'message': 'No health check available'}
            
            health_status[name] = status
            
        except Exception as e:
            health_status[name] = {
                'status': 'error',
                'message': str(e),
                'last_check': datetime.utcnow().isoformat()
            }
    
    overall_healthy = all(
        status.get('status') == 'healthy' 
        for status in health_status.values()
    )
    
    return {
        'overall_status': 'healthy' if overall_healthy else 'degraded',
        'integrations': health_status,
        'timestamp': datetime.utcnow().isoformat()
    }

@router.post("/integrations/{integration_name}/test")
async def test_integration(
    integration_name: str,
    test_data: dict = None,
    current_user: User = Depends(get_current_admin)
):
    """Test specific integration with sample data"""
    if integration_name not in integration_manager.integrations:
        raise HTTPException(status_code=404, detail="Integration not found")
    
    integration = integration_manager.integrations[integration_name]
    
    try:
        if integration_name == 'slack':
            result = await integration.send_threat_alert(test_data or get_sample_threat_data())
        elif integration_name == 'splunk':
            result = await integration.send_threat_event(test_data or get_sample_threat_data())
        else:
            result = await integration.test_connection()
        
        return {
            'status': 'success',
            'integration': integration_name,
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Integration test failed for {integration_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")
```

## Best Practices

### Security Considerations

1. **Credential Management**
   - Store API keys and secrets in secure vaults (HashiCorp Vault, Azure Key Vault)
   - Use environment variables for sensitive configuration
   - Implement credential rotation policies

2. **Rate Limiting**
   - Implement rate limiting to respect API quotas
   - Use exponential backoff for retries
   - Monitor API usage and costs

3. **Error Handling**
   - Implement comprehensive error handling and logging
   - Use circuit breakers for external API calls
   - Provide graceful degradation when integrations fail

4. **Monitoring**
   - Monitor integration health and performance
   - Set up alerts for integration failures
   - Track API usage and rate limits

### Performance Optimization

1. **Batch Processing**
   - Use batch APIs when available
   - Implement intelligent batching based on API limits
   - Process data in parallel when possible

2. **Caching**
   - Cache frequently accessed data (user info, threat intel)
   - Implement cache invalidation strategies
   - Use Redis for distributed caching

3. **Asynchronous Processing**
   - Use async/await for non-blocking operations
   - Implement task queues for heavy operations
   - Process integrations in parallel

For additional integration support or custom integrations, contact our integration team at integrations@phishguard.com.
