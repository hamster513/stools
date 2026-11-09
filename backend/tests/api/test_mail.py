"""SMTP settings, permissions and shared transport; no external email is sent."""
import smtplib
import ssl
from unittest.mock import MagicMock

import pytest

from api.db.models import AppSetting

URL = '/api/settings/mail'
CONFIG = {'enabled': True, 'host': 'smtp.example.test', 'port': 587, 'security': 'starttls',
          'from_address': 'stools@example.test', 'from_name': 'STools', 'auth_enabled': True,
          'username': 'mailer', 'password': 'test-mail-secret', 'timeout': 10}


def test_defaults_and_encrypted_secret_lifecycle(auth_client, db_session):
    response = auth_client.get(URL)
    assert response.status_code == 200
    assert response.json()['enabled'] is False
    assert response.json()['has_password'] is False
    assert auth_client.put(URL, json=CONFIG).status_code == 204
    value = db_session.get(AppSetting, 'mail.password').value_json
    assert value.startswith('enc:v1:') and CONFIG['password'] not in value
    assert 'password' not in auth_client.get(URL).json()
    assert auth_client.get(URL).json()['has_password'] is True
    assert CONFIG['password'] not in db_session.get(AppSetting, 'mail').value_json
    update = {**CONFIG, 'password': None, 'from_name': 'New name'}
    assert auth_client.put(URL, json=update).status_code == 204
    db_session.expire_all()
    assert db_session.get(AppSetting, 'mail.password').value_json == value
    update.update(auth_enabled=False, password='')
    assert auth_client.put(URL, json=update).status_code == 204
    assert auth_client.get(URL).json()['has_password'] is False


@pytest.mark.parametrize('change', [
    {'port': 0}, {'port': 65536}, {'timeout': 0}, {'host': 'https://smtp.example.test'},
    {'from_address': 'a@example.test\r\nBcc: victim@example.test'}, {'from_address': 'bad'},
    {'from_name': 'Bad\nheader'}, {'security': 'auto'}, {'host': ''}, {'extra': True},
    {'auth_enabled': True, 'username': ''},
])
def test_invalid_settings_rejected(auth_client, change):
    assert auth_client.put(URL, json={**CONFIG, **change}).status_code == 422


def test_password_requires_encryption_key(auth_client, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr('api.platform.mail.get_settings', lambda: SimpleNamespace(session_secret=''))
    response = auth_client.put(URL, json=CONFIG)
    assert response.status_code == 400
    assert CONFIG['password'] not in response.text


@pytest.mark.parametrize('method,path', [('GET', URL), ('PUT', URL), ('POST', URL+'/test')])
def test_anonymous_denied(client, method, path):
    assert client.request(method, path, json={}).status_code == 401


def test_reader_cannot_save_or_send(client_as):
    client = client_as({'platform': 'read'})
    assert client.get(URL).status_code == 200
    assert client.put(URL, json=CONFIG).status_code == 403
    assert client.post(URL+'/test', json={}).status_code == 403


def smtp_mock(monkeypatch):
    from api.platform import mail
    smtp = MagicMock()
    smtp.send_message.return_value = {}
    factory = MagicMock(return_value=smtp)
    monkeypatch.setattr(mail.smtplib, 'SMTP', factory)
    monkeypatch.setattr(mail.smtplib, 'SMTP_SSL', factory)
    return smtp, factory


@pytest.mark.parametrize('security', ['starttls', 'tls', 'none'])
def test_transport_modes_and_unicode_message(auth_client, db_session, monkeypatch, security):
    from api.platform.mail import send_email
    smtp, factory = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json={**CONFIG, 'security': security}).status_code == 204
    message_id = send_email(db_session, to=['user@example.test'], subject='Новая угроза', text='Описание угрозы')
    assert message_id.startswith('<')
    kwargs = factory.call_args.kwargs
    assert kwargs['timeout'] == 10
    if security == 'tls':
        assert kwargs['context'].verify_mode == ssl.CERT_REQUIRED
    if security == 'starttls':
        assert smtp.starttls.call_args.kwargs['context'].verify_mode == ssl.CERT_REQUIRED
        calls = [c[0] for c in smtp.mock_calls]
        assert calls.index('starttls') < calls.index('login') < calls.index('send_message')
    else:
        smtp.starttls.assert_not_called()
    smtp.login.assert_called_once_with('mailer', CONFIG['password'])
    msg = smtp.send_message.call_args.args[0]
    assert msg['Subject'] == 'Новая угроза'
    assert 'Описание угрозы' in msg.get_content()
    assert msg['Message-ID'] == message_id
    assert smtp.send_message.call_args.kwargs['to_addrs'] == ['user@example.test']
    smtp.close.assert_called_once()


def test_disabled_transport_never_connects(auth_client, db_session, monkeypatch):
    from api.platform.mail import MailError, send_email
    _, factory = smtp_mock(monkeypatch)
    with pytest.raises(MailError, match='выключена'):
        send_email(db_session, to=['user@example.test'], subject='Test', text='Body')
    factory.assert_not_called()


def test_test_mail_uses_unsaved_form_and_saved_password(auth_client, monkeypatch):
    smtp, factory = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json=CONFIG).status_code == 204
    settings = {**CONFIG, 'enabled': False, 'password': None, 'from_name': 'Unsaved name'}
    response = auth_client.post(URL+'/test', json={'settings': settings, 'recipient': 'user@example.test'})
    assert response.status_code == 200, response.text
    assert response.json()['accepted'] is True
    assert factory.call_args.kwargs['host'] == CONFIG['host']
    smtp.login.assert_called_once_with('mailer', CONFIG['password'])
    assert auth_client.get(URL).json()['host'] == CONFIG['host']


@pytest.mark.parametrize('error,expected', [
    (smtplib.SMTPAuthenticationError(535, b'test-mail-secret'), 'авторизац'),
    (smtplib.SMTPNotSupportedError('STARTTLS secret'), 'поддерживает'),
    (TimeoutError('test-mail-secret'), 'время'),
    (ssl.SSLCertVerificationError('test-mail-secret'), 'сертификат'),
    (smtplib.SMTPDataError(550, b'test-mail-secret'), 'отклонил'),
])
def test_safe_errors_and_no_retries(auth_client, monkeypatch, error, expected):
    smtp, factory = smtp_mock(monkeypatch)
    smtp.send_message.side_effect = error
    response = auth_client.post(URL+'/test', json={'settings': CONFIG, 'recipient': 'user@example.test'})
    assert response.status_code == 502
    assert expected in response.json()['detail']
    assert CONFIG['password'] not in response.text
    assert factory.call_count == 1
    smtp.close.assert_called_once()


def test_relay_no_login_and_partial_refusal_is_not_success(auth_client, db_session, monkeypatch):
    from api.platform.mail import MailError, send_email
    smtp, _ = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json={**CONFIG, 'auth_enabled': False}).status_code == 204
    smtp.send_message.return_value = {'bad@example.test': (550, b'private server response')}
    with pytest.raises(MailError, match='часть'):
        send_email(db_session, to=['good@example.test', 'bad@example.test'], subject='Test', text='Body')
    smtp.login.assert_not_called()
    smtp.send_message.assert_called_once()


@pytest.mark.parametrize('recipient', ['bad', 'a@example.test\nBcc:x@example.test', 'a@example.test,b@example.test'])
def test_invalid_test_recipient_never_connects(auth_client, monkeypatch, recipient):
    _, factory = smtp_mock(monkeypatch)
    assert auth_client.post(URL+'/test', json={'settings': CONFIG, 'recipient': recipient}).status_code == 422
    factory.assert_not_called()


def test_changed_server_requires_password_again(auth_client, monkeypatch):
    _, factory = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json=CONFIG).status_code == 204
    changed = {**CONFIG, 'host': 'other.example.test', 'password': None}
    assert auth_client.put(URL, json=changed).status_code == 422
    assert auth_client.post(URL+'/test', json={'settings': changed, 'recipient': 'user@example.test'}).status_code == 422
    factory.assert_not_called()
    assert auth_client.put(URL, json={**changed, 'password': 'new-password'}).status_code == 204


def test_service_validates_headers_before_network(auth_client, db_session, monkeypatch):
    from api.platform.mail import send_email
    _, factory = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json=CONFIG).status_code == 204
    with pytest.raises(ValueError):
        send_email(db_session, to=['user@example.test'], subject='Bad\r\nBcc: x@example.test', text='Body')
    factory.assert_not_called()


def test_invalid_form_does_not_echo_password(auth_client):
    response = auth_client.put(URL, json={**CONFIG, 'host': ''})
    assert response.status_code == 422
    assert CONFIG['password'] not in response.text


def test_real_smtp_relay_accepts_mime_message(auth_client):
    """Local in-process SMTP peer verifies the actual smtplib/MIME path."""
    import queue
    import socketserver
    import threading
    from email import policy
    from email.parser import BytesParser

    received = queue.Queue()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            self.wfile.write(b'220 local test relay\r\n')
            while line := self.rfile.readline():
                verb = line.split(b' ', 1)[0].strip().upper()
                if verb in (b'EHLO', b'HELO'):
                    self.wfile.write(b'250 localhost\r\n')
                elif verb in (b'MAIL', b'RCPT'):
                    self.wfile.write(b'250 OK\r\n')
                elif verb == b'DATA':
                    self.wfile.write(b'354 send data\r\n')
                    body = []
                    while (chunk := self.rfile.readline()) not in (b'.\r\n', b''):
                        body.append(chunk[1:] if chunk.startswith(b'..') else chunk)
                    received.put(b''.join(body))
                    self.wfile.write(b'250 accepted\r\n')
                elif verb == b'QUIT':
                    self.wfile.write(b'221 bye\r\n')
                    return
                else:
                    self.wfile.write(b'500 unsupported\r\n')

    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = {**CONFIG, 'enabled': False, 'host': '127.0.0.1', 'port': server.server_address[1],
                      'security': 'none', 'auth_enabled': False, 'password': None, 'from_name': 'Тест STools'}
            response = auth_client.post(URL+'/test', json={'settings': config, 'recipient': 'local@example.test'})
            assert response.status_code == 200, response.text
            message = BytesParser(policy=policy.default).parsebytes(received.get(timeout=2))
            assert message['Subject'] == 'STools: проверка почты'
            assert message['From'].addresses[0].display_name == 'Тест STools'
            assert message['To'] == 'local@example.test'
            assert message['Message-ID'] == response.json()['message_id']
            assert 'Тестовое письмо STools' in message.get_content()
            assert auth_client.get(URL).json()['host'] == ''
        finally:
            server.shutdown()
            thread.join(timeout=5)


def test_unreadable_stored_password_never_connects(auth_client, db_session, monkeypatch):
    from api.crypto import SecretUnreadable
    from api.platform.mail import MailError, send_email
    _, factory = smtp_mock(monkeypatch)
    assert auth_client.put(URL, json=CONFIG).status_code == 204
    def unreadable(_):
        raise SecretUnreadable()
    monkeypatch.setattr('api.platform.mail.decrypt', unreadable)
    with pytest.raises(MailError, match='не расшифровывается'):
        send_email(db_session, to=['user@example.test'], subject='Test', text='Body')
    assert auth_client.get(URL).json()['has_password'] is True
    factory.assert_not_called()


def test_non_ascii_smtp_auth_error_is_safe(auth_client, monkeypatch):
    smtp, _ = smtp_mock(monkeypatch)
    smtp.login.side_effect = UnicodeEncodeError('ascii', 'private-password', 0, 16, 'not supported')
    response = auth_client.post(URL+'/test', json={'settings': CONFIG, 'recipient': 'user@example.test'})
    assert response.status_code == 502
    assert 'private-password' not in response.text
    assert 'кодировк' in response.json()['detail']
