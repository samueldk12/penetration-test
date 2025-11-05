#!/usr/bin/env python3
"""
Notification System
Sistema de notificações via Telegram, WhatsApp, Email
"""

import requests
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, Optional, List
from pathlib import Path
import json


class NotificationSystem:
    """Sistema de notificações multi-canal."""

    def __init__(self, config: Dict):
        """
        Inicializa sistema de notificações.

        Args:
            config: Configurações de notificações
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        self.logger = logging.getLogger(__name__)

        # Configurações de canais
        self.telegram_config = config.get('telegram', {})
        self.whatsapp_config = config.get('whatsapp', {})
        self.email_config = config.get('email', {})
        self.webhook_config = config.get('webhook', {})

    def send_notification(self, message: str, **kwargs) -> Dict:
        """
        Envia notificação para todos os canais habilitados.

        Args:
            message: Mensagem a enviar
            **kwargs: Opções adicionais
                - title: Título da notificação
                - priority: 'low', 'normal', 'high', 'critical'
                - attachments: Lista de arquivos para anexar (email)
                - report_data: Dados do relatório (dict)

        Returns:
            Dict com resultados do envio
        """
        if not self.enabled:
            self.logger.debug("Notifications disabled")
            return {'success': True, 'message': 'Notifications disabled'}

        results = {
            'telegram': None,
            'whatsapp': None,
            'email': None,
            'webhook': None
        }

        title = kwargs.get('title', 'Pentest Notification')
        priority = kwargs.get('priority', 'normal')

        # Telegram
        if self.telegram_config.get('enabled', False):
            results['telegram'] = self._send_telegram(title, message, priority)

        # WhatsApp
        if self.whatsapp_config.get('enabled', False):
            results['whatsapp'] = self._send_whatsapp(title, message, priority)

        # Email
        if self.email_config.get('enabled', False):
            attachments = kwargs.get('attachments', [])
            results['email'] = self._send_email(title, message, attachments, priority)

        # Webhook genérico
        if self.webhook_config.get('enabled', False):
            report_data = kwargs.get('report_data', {})
            results['webhook'] = self._send_webhook(title, message, report_data, priority)

        return {
            'success': any(r and r.get('success') for r in results.values() if r),
            'results': results
        }

    def _send_telegram(self, title: str, message: str, priority: str) -> Dict:
        """Envia notificação via Telegram Bot API."""
        bot_token = self.telegram_config.get('bot_token')
        chat_id = self.telegram_config.get('chat_id')

        if not bot_token or not chat_id:
            return {
                'success': False,
                'error': 'Telegram bot_token or chat_id not configured'
            }

        try:
            # Formata mensagem
            emoji = self._get_priority_emoji(priority)
            formatted_message = f"{emoji} *{title}*\n\n{message}"

            # Envia via API
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

            payload = {
                'chat_id': chat_id,
                'text': formatted_message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True
            }

            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            self.logger.info("Telegram notification sent")

            return {
                'success': True,
                'channel': 'telegram',
                'message_id': response.json().get('result', {}).get('message_id')
            }

        except requests.RequestException as e:
            self.logger.error(f"Telegram notification failed: {e}")
            return {
                'success': False,
                'channel': 'telegram',
                'error': str(e)
            }

    def _send_whatsapp(self, title: str, message: str, priority: str) -> Dict:
        """
        Envia notificação via WhatsApp (usando Twilio ou CallMeBot).

        Nota: WhatsApp Business API requer aprovação.
        Usando CallMeBot como alternativa simples.
        """
        api_key = self.whatsapp_config.get('api_key')
        phone = self.whatsapp_config.get('phone')

        if not api_key or not phone:
            return {
                'success': False,
                'error': 'WhatsApp api_key or phone not configured'
            }

        try:
            # CallMeBot API (método simples)
            emoji = self._get_priority_emoji(priority)
            formatted_message = f"{emoji} {title}\n\n{message}"

            url = "https://api.callmebot.com/whatsapp.php"

            params = {
                'phone': phone,
                'text': formatted_message,
                'apikey': api_key
            }

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                self.logger.info("WhatsApp notification sent")
                return {
                    'success': True,
                    'channel': 'whatsapp'
                }
            else:
                return {
                    'success': False,
                    'channel': 'whatsapp',
                    'error': f'HTTP {response.status_code}'
                }

        except requests.RequestException as e:
            self.logger.error(f"WhatsApp notification failed: {e}")
            return {
                'success': False,
                'channel': 'whatsapp',
                'error': str(e)
            }

    def _send_email(self, title: str, message: str,
                   attachments: List[str], priority: str) -> Dict:
        """Envia notificação via Email."""
        smtp_host = self.email_config.get('smtp_host')
        smtp_port = self.email_config.get('smtp_port', 587)
        smtp_user = self.email_config.get('smtp_user')
        smtp_password = self.email_config.get('smtp_password')
        from_email = self.email_config.get('from_email', smtp_user)
        to_emails = self.email_config.get('to_emails', [])

        if not all([smtp_host, smtp_user, smtp_password, to_emails]):
            return {
                'success': False,
                'error': 'Email configuration incomplete'
            }

        try:
            # Cria mensagem
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(to_emails) if isinstance(to_emails, list) else to_emails
            msg['Subject'] = f"{self._get_priority_text(priority)} {title}"

            # Corpo da mensagem
            body = MIMEText(message, 'plain', 'utf-8')
            msg.attach(body)

            # Anexos
            for attachment_path in attachments:
                if Path(attachment_path).exists():
                    with open(attachment_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename={Path(attachment_path).name}'
                        )
                        msg.attach(part)

            # Envia email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

            self.logger.info(f"Email sent to {len(to_emails)} recipient(s)")

            return {
                'success': True,
                'channel': 'email',
                'recipients': len(to_emails)
            }

        except Exception as e:
            self.logger.error(f"Email notification failed: {e}")
            return {
                'success': False,
                'channel': 'email',
                'error': str(e)
            }

    def _send_webhook(self, title: str, message: str,
                     report_data: Dict, priority: str) -> Dict:
        """Envia notificação via webhook genérico."""
        webhook_url = self.webhook_config.get('url')

        if not webhook_url:
            return {
                'success': False,
                'error': 'Webhook URL not configured'
            }

        try:
            payload = {
                'title': title,
                'message': message,
                'priority': priority,
                'timestamp': self._get_timestamp(),
                'report_data': report_data
            }

            # Headers customizados
            headers = self.webhook_config.get('headers', {})
            headers['Content-Type'] = 'application/json'

            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()

            self.logger.info("Webhook notification sent")

            return {
                'success': True,
                'channel': 'webhook',
                'status_code': response.status_code
            }

        except requests.RequestException as e:
            self.logger.error(f"Webhook notification failed: {e}")
            return {
                'success': False,
                'channel': 'webhook',
                'error': str(e)
            }

    def send_scan_complete(self, summary: Dict, report_files: List[str] = None) -> Dict:
        """
        Envia notificação de scan completo.

        Args:
            summary: Resumo do scan
            report_files: Lista de arquivos de relatório

        Returns:
            Dict com resultados
        """
        if not self.config.get('notify_on_complete', True):
            return {'success': True, 'message': 'Notify on complete disabled'}

        target = summary.get('target', 'Unknown')
        total_plugins = summary.get('total_plugins', 0)
        success_rate = summary.get('success_rate', 0)
        total_time = summary.get('total_time', 0)

        # Findings
        total_urls = summary.get('total_urls_found', 0)
        total_subdomains = summary.get('total_subdomains_found', 0)
        total_secrets = summary.get('total_secrets_found', 0)
        total_vulns = summary.get('total_vulnerabilities_found', 0)

        message = f"""
Scan Completed Successfully!

Target: {target}
Duration: {total_time:.2f} seconds

Plugins Executed: {total_plugins}
Success Rate: {success_rate:.1f}%

Findings:
• URLs: {total_urls}
• Subdomains: {total_subdomains}
• Secrets/API Keys: {total_secrets}
• Vulnerabilities: {total_vulns}

Reports generated and saved.
"""

        return self.send_notification(
            message.strip(),
            title="🎯 Pentest Scan Complete",
            priority='normal' if total_vulns == 0 else 'high',
            attachments=report_files or [],
            report_data=summary
        )

    def send_error_notification(self, error_message: str, context: Dict = None) -> Dict:
        """
        Envia notificação de erro.

        Args:
            error_message: Mensagem de erro
            context: Contexto adicional do erro

        Returns:
            Dict com resultados
        """
        if not self.config.get('notify_on_error', True):
            return {'success': True, 'message': 'Notify on error disabled'}

        message = f"""
Error During Scan!

Error: {error_message}
"""

        if context:
            message += f"\nContext:\n{json.dumps(context, indent=2)}"

        return self.send_notification(
            message.strip(),
            title="❌ Pentest Error",
            priority='critical',
            report_data={'error': error_message, 'context': context}
        )

    def send_critical_finding(self, finding: Dict) -> Dict:
        """
        Envia notificação de finding crítico.

        Args:
            finding: Dados do finding

        Returns:
            Dict com resultados
        """
        if not self.config.get('notify_on_critical', True):
            return {'success': True, 'message': 'Notify on critical disabled'}

        vuln_type = finding.get('type', 'Unknown')
        target = finding.get('target', 'Unknown')
        description = finding.get('description', 'No description')

        message = f"""
Critical Vulnerability Found!

Type: {vuln_type}
Target: {target}

Description:
{description}

Immediate action recommended!
"""

        return self.send_notification(
            message.strip(),
            title="🚨 Critical Finding",
            priority='critical',
            report_data=finding
        )

    def _get_priority_emoji(self, priority: str) -> str:
        """Retorna emoji baseado na prioridade."""
        emojis = {
            'low': 'ℹ️',
            'normal': '📢',
            'high': '⚠️',
            'critical': '🚨'
        }
        return emojis.get(priority, '📢')

    def _get_priority_text(self, priority: str) -> str:
        """Retorna texto de prioridade."""
        texts = {
            'low': '[INFO]',
            'normal': '[NOTICE]',
            'high': '[WARNING]',
            'critical': '[CRITICAL]'
        }
        return texts.get(priority, '[NOTICE]')

    def _get_timestamp(self) -> str:
        """Retorna timestamp atual."""
        from datetime import datetime
        return datetime.now().isoformat()

    def test_notifications(self) -> Dict:
        """Testa todas as configurações de notificação."""
        results = {}

        test_message = "This is a test notification from Pentest Suite"

        if self.telegram_config.get('enabled', False):
            results['telegram'] = self._send_telegram(
                "Test Notification",
                test_message,
                'normal'
            )

        if self.whatsapp_config.get('enabled', False):
            results['whatsapp'] = self._send_whatsapp(
                "Test Notification",
                test_message,
                'normal'
            )

        if self.email_config.get('enabled', False):
            results['email'] = self._send_email(
                "Test Notification",
                test_message,
                [],
                'normal'
            )

        if self.webhook_config.get('enabled', False):
            results['webhook'] = self._send_webhook(
                "Test Notification",
                test_message,
                {},
                'normal'
            )

        return {
            'success': any(r.get('success') for r in results.values()),
            'results': results
        }


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Notification System')
    parser.add_argument('--test', action='store_true',
                       help='Test notification configuration')
    parser.add_argument('--message', help='Send test message')
    parser.add_argument('--config', default='config.yaml',
                       help='Configuration file')

    args = parser.parse_args()

    # Load config
    try:
        import yaml
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
            notif_config = config.get('notifications', {})
    except Exception as e:
        print(f"Error loading config: {e}")
        print("Using default configuration")
        notif_config = {'enabled': False}

    notifier = NotificationSystem(notif_config)

    if args.test:
        print("Testing notification channels...")
        results = notifier.test_notifications()
        print(json.dumps(results, indent=2))

    elif args.message:
        print(f"Sending message: {args.message}")
        result = notifier.send_notification(args.message, title="Test Message")
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()
