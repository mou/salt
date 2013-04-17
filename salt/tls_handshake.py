'''
This module contains our 'TLS over zmq' implementation for both the client
(minion) and the server (master).
'''

#Import python libs
import datetime
import hashlib
import hmac
import logging
import os
import re

#Import Cryptography libs
from subprocess import Popen, PIPE
from M2Crypto import RSA, X509

#Import salt utils
import salt.utils
import salt.payload
import salt.utils.verify
from salt.exceptions import AuthenticationError, SaltClientError, SaltReqTimeoutError

import msgpack

log = logging.getLogger(__name__)

def do_client_handshake(sreq, opts):
    log.debug('Starting client TLS handshake...')
    client = ClientHandshake(opts, sreq)
    return client.handshake()

class HandshakeHash(object):
    def __init__(self):
        self._hmac = hmac.new("...", digestmod=hashlib.sha256)
        self.messages = []

    def update(self, data):
        for msg in data:
            if msg['type'] == 'handshake':
                log.debug('Adding {message} to digest'.format(**msg))
                self.messages.append(msg['message'])
                self._hmac.update(self.flatten(msg))

    def flatten(self, msg):
        '''
        Convert message to a stable-sorted string we can hash
        '''
        return str([(str(k), str(msg[k])) for k in sorted(msg.iterkeys())])

    def digest(self):
        log.debug(self.messages)
        return self._hmac.hexdigest()



class Handshake(object):
    def __init__(self, opts, id=None):
        self.hash = HandshakeHash()
        self.protocol = '1'
        self.cipher = 'rsa/null/sha-256'
        if id is None:
            self.id = self.random()
        else:
            self.id = id
        self.certificate = X509.load_cert(opts['x509']['cert'])
        self.public_key = self.certificate.get_pubkey().get_rsa().as_pem()
        self.private_key = RSA.load_key(opts['x509']['key'])
        self.ca_cert_path = opts['x509']['ca_cert']
        self.ca_cert = X509.load_cert(self.ca_cert_path)
        self.issuer_dn_match = None
        if 'issuer_dn_match' in opts['x509']:
            self.issuer_dn_match = re.compile(
                opts['x509']['issuer_dn_match']
            )

        self.subject_dn_match = None
        if 'subject_dn_match' in opts['x509']:
            self.subject_dn_match = re.compile(
                opts['x509']['subject_dn_match']
            )
        self.opts = opts


    def random(self):
        return datetime.datetime.utcnow().isoformat() + os.urandom(28)


    def verify_client_cert(self, client_cert, client_encrypted_token=None):
        '''
        Returns True if the client certificate is valid and passes any issuer
        or subject constraints.
        '''
        if not 'x509' in self.opts:
            return False

        log.debug('Loading client certificate...')

        if not self.verify_via_openssl(client_cert):
            log.error('Client certificate was not valid')
            return False
            # Cert is valid, is it appropriate?
        if self.issuer_dn_match and\
           not self.issuer_dn_match.match(
               client_cert.get_issuer().as_text()):
            log.error('Client certificate\'s Issuer did not match')
            return False
        if self.subject_dn_match and\
           not self.subject_dn_match.match(
               client_cert.get_subject().as_text()):
            log.error('Client certificate\'s Subject did not match')
            return False
        if client_encrypted_token:
            log.debug('Checking minion x509 token...')
            clear_token = client_cert.get_pubkey().get_rsa().public_decrypt(client_encrypted_token, 5)
            if clear_token != 'salty cert':
                log.error('Minion token did not match')
                return False

        log.debug('Client certificate verified')
        return True

    def verify_via_openssl(self, certificate):
        p1 = Popen(["openssl", "verify", "-CAfile", self.ca_cert_path],
           stdin = PIPE, stdout = PIPE, stderr = PIPE)

        message, error = p1.communicate(certificate.as_pem())
        return ("OK" in message and not "error" in message)



class ClientHandshake(Handshake):
    def __init__(self, opts, sreq):
        super(ClientHandshake, self).__init__(opts)
        self.client_random = self.random()
        self.sreq = sreq
        self.minion_id = opts['id']

        self.server_random = None
        self.server_certificate = None

    def handshake(self):
        log.debug('Starting TLS handshake...')
        response = self.send_hello()
        self.parse_server_hello(response)

        response = self.send_key_exchange()
        result = self.parse_server_key_exchange(response)
        if result != True:
            return result

        response = self.send_finished()
        result = self.parse_server_finished(response)
        return {'publish_port': result['publish_port'],
                'cert': self.certificate,
                'key': self.private_key,
                'opposite_cert': self.server_certificate_string}

    def send_hello(self):
        log.debug('Sending hello...')
        response = self.send(
            sequence='hello',
            data=[
                {
                    'type' : 'handshake',
                    'message' : 'ClientHello',
                    'protocol' : self.protocol,
                    'random' : self.client_random,
                    'cipher' : self.cipher
                }
            ]
        )
        return response

    def parse_server_hello(self, response):
        log.debug('Parsing hello reply...')
        try:
            (server_hello, certificate, cert_request, server_hello_done) = self.parse_response(response)
        except ValueError:
            return self.error('Unexpected messages in ClientHello response')

        # check server_hello
        if server_hello['message'] != 'ServerHello':
            return self.error('Unexpected server message: {message}'.format(**server_hello))

        if server_hello['cipher'] != self.cipher or server_hello['protocol'] != self.protocol:
            return self.error('Unsupported Protocol={protocol} Cipher={cipher}'.format(**server_hello))
        self.server_random = server_hello['random']

        #check server cert
        if certificate['message'] != 'Certificate':
            return self.error('Unexpected message: {message}'.format(certificate))
        try:
            self.server_certificate_string = certificate['certificate']
            self.server_certificate = X509.load_cert_string(certificate['certificate'])
            self.verify_client_cert(self.server_certificate)
        except:
            return self.error('Server certificate invalid')

        #check server cert request
        if cert_request['message'] != 'CertificateRequest':
            return self.error('Unexpected message: {message}'.format(cert_request))
        if cert_request['certificate_type'] != 'rsa-sign':
            return self.error('Unexpected certificate type: {certificate_type}'.format(**cert_request))
        if cert_request['ca'] != self.certificate.get_issuer().as_text():
            return self.error('Client certificate not from acceptable CA')

        #server hello done
        if server_hello_done['message'] != 'ServerHelloDone':
            return self.error('Unexpected message: {message}'.format(**server_hello_done))

        return True

    def send_key_exchange(self):
        log.debug('Sending key_exchange...')
        client_premaster_secret = os.urandom(46)
        data = [
            {
                'type' : 'handshake',
                'message' : 'Certificate',
                'certificate' : self.certificate.as_pem()
            },
            {
                'type' : 'handshake',
                'message' : 'ClientKeyExchange',
                'encrypted' : self.server_certificate.get_pubkey().get_rsa().public_encrypt(client_premaster_secret, 4)
            }
        ]
        self.hash.update(data)
        cert_verify_msg = {
            'type' : 'handshake',
            'message' : 'CertificateVerify',
            'digest' : self.hash.digest(),
            'digest_signature' : self.private_key.sign(self.hash.digest())
        }
        data.append(cert_verify_msg)
        self.hash.update([cert_verify_msg])
        response = self.send(
            sequence='key_exchange',
            data=data,
            do_hash=False
        )
        return response

    def parse_server_key_exchange(self, response):
        log.debug('Parsing key_exchange reply...')
        (ok,) = self.parse_response(response)
        #make sure response is not an error (shouldn't contain any handshake messages
        if ok['type'] != 'ok':
            return self.error('Server did not accept ClientKeyExchange')
        return True

    def send_finished(self):
        log.debug('Sending finished...')
        # complete the handshake
        response = self.send(
            sequence='finished',
            data=[
                {
                    'type' : 'cipher',
                    'message' : 'ChangeCipherSpec'
                },
                {
                    'type' : 'handshake',
                    'message' : 'Finished',
                    'encrypted' : self.server_certificate.get_pubkey().get_rsa().public_encrypt(self.hash.digest(), 4)
                }
            ]
        )
        return response

    def parse_server_finished(self, response):
        pre_finished_digest = self.hash.digest()

        log.debug('Parsing finished reply...')
        try:
            (server_cipher_spec, server_finished, app_msg) = self.parse_response(response)
        except ValueError:
            return self.error('Unexpected final response sequence from server')

        # server cipher spec
        if server_cipher_spec['type'] != 'cipher' or server_cipher_spec['message'] != 'ChangeCipherSpec':
            return self.error('Server did not explicitly change cipher spec')

        # server finished
        if server_finished['message'] != 'Finished':
            return self.error('Unexpected message: {message}'.format(**server_finished))

        server_digest = self.private_key.private_decrypt(server_finished['encrypted'], 4)
        if server_digest != pre_finished_digest:
            return self.error('Client and Server do not agree on handshake digest')

        if app_msg['type'] != 'app':
            return self.error('Expected application message with master info')

        app_payload = decrypt_with_private_key(self.private_key, app_msg['encrypted'])
        auth = msgpack.loads(app_payload)
        return {
            'aes' : auth['aes'],
            'publish_port' : auth['publish_port']
        }

    def send(self, sequence, data, result=None, do_hash=True):
        log.debug(data)
        if do_hash:
            self.hash.update(data)
        payload = {
            'cmd': '_auth',
            'sequence' : sequence,
            'session_id' : self.id,
            'id' : self.minion_id,
            'pub' : self.public_key,
            'data' : data
        }
        if result is not None:
            payload['result'] = result
        return self.sreq.send('clear', payload)

    def error(self, error):
        log.debug(error)
        return {
            'error' :  error
        }

    def parse_response(self, response):
        log.debug(response)
        if 'load' not in response or 'data' not in response['load']:
            return []
        data = response['load']['data']
        self.hash.update(data)
        return data

class ServerHandshake(Handshake):
    def __init__(self, client_id, opts):
        super(ServerHandshake, self).__init__(opts, client_id)

    def process(self, load):
        if 'sequence' not in load:
            return self.error('invalid handshake packet')
        sequence = load['sequence']
        data = load['data']

        sequences = {
            'hello' : self.hello,
            'key_exchange' : self.key_exchange,
            'finished' : self.finished
        }

        if sequence in sequences:
            log.debug(sequence)
            return sequences[sequence](data)
        else:
            log.error(sequence)
            return self.error('invalid handshake sequence')

    def error(self, error):
        log.debug(error)
        return {
            'enc' : 'clear',
            'result' : False,
            'load' : {
                'error' : error
            }
        }

    def reply(self, data, result=None):
        self.hash.update(data)
        response = {
            'enc' : 'clear',
            'load' : {
                'data' : data
            }
        }
        if result is not None:
            response['result'] = result
        return response

    def hello(self, data):
        try:
            (client_hello,) = data
        except ValueError:
            return self.error('Unexpected hello sequence data')
        self.hash.update(data)
        if client_hello['message'] != 'ClientHello':
            return self.error('First message was not ClientHello')

        if client_hello['protocol'] != self.protocol or client_hello['cipher'] != self.cipher:
            return self.error('Unsupported client cipher')

        return self.reply([
            {
                'type' : 'handshake',
                'message' : 'ServerHello',
                'protocol' : self.protocol,
                'random' : self.random(),
                'cipher' : self.cipher
            },
            {
                'type' : 'handshake',
                'message' : 'Certificate',
                'certificate' : self.certificate.as_pem()
            },
            {
                'type' : 'handshake',
                'message' : 'CertificateRequest',
                'certificate_type' : 'rsa-sign',
                'ca' : self.ca_cert.get_issuer().as_text()
            },
            {
                'type' : 'handshake',
                'message' : 'ServerHelloDone'
            }
        ])

    def key_exchange(self, data):
        try:
            (certificate, key_exchange, cert_verify) = data
        except ValueError:
            return self.error('Unexpected key_exchange sequence data')
        self.hash.update([certificate, key_exchange])

        pre_verify_digest = self.hash.digest()
        self.hash.update([cert_verify])

        self.client_certificate = X509.load_cert_string(certificate['certificate'])
        if not self.verify_client_cert(self.client_certificate):
            return self.error("Client certificate fails validation against CA")
        client_premaster_secret = self.private_key.private_decrypt(key_exchange['encrypted'], 4)

        client_digest = cert_verify['digest']
        client_signature = cert_verify['digest_signature']
        if not self.client_certificate.get_pubkey().get_rsa().verify(client_digest, client_signature):
            return self.error('Client digest signature failed')

        if client_digest != pre_verify_digest:
            return self.error('digest mismatch')

        return self.reply(
            [
                {
                    'type' : 'ok'
                }
            ]
        )

    def finished(self, data):

        before_finished_digest = self.hash.digest()

        try:
            (client_cipher_spec, client_finished) = data
        except ValueError:
            return self.error('Unexpected finish sequence data')
        self.hash.update(data)

        # server cipher spec
        if client_cipher_spec['type'] != 'cipher' or client_cipher_spec['message'] != 'ChangeCipherSpec':
            return self.error('Client did not explicitly change cipher spec')

        if client_finished['message'] != 'Finished':
            return self.error('Client did not send expected Finished message')

        client_digest = self.private_key.private_decrypt(client_finished['encrypted'], 4)
        if client_digest != before_finished_digest:
            return self.error('Client and Server do not agree on handshake digest')

        return self.reply(
            [
                {
                    'type' : 'cipher',
                    'message' : 'ChangeCipherSpec'
                },
                {
                    'type' : 'handshake',
                    'message' : 'Finished',
                    'encrypted' : self.client_certificate.get_pubkey().get_rsa().public_encrypt(self.hash.digest(), 4)
                },
                {
                    'type' : 'app',
                    'encrypted' : encrypt_with_public_key(self.client_certificate.get_pubkey().get_rsa(),
                        msgpack.dumps(
                            {
                                'aes' : self.opts['aes'],
                                'publish_port' : self.opts['publish_port']

                            }
                        )
                    )
                }
            ],
            result=True
        )



class TLSFuncs(object):
    '''
    Master functions used when the payload is 'encrypted' with 'tls'
    '''
    def __init__(self, opts):
        self.in_progress_handshakes = {}
        self.opts = opts

    def _handshake(self, load, transport):
        log.debug('TLS handshake from client {session_id}'.format(**load))
        client_id = load['session_id']
        if client_id not in self.in_progress_handshakes:
            log.debug('Creating new handshake session')
            log.debug(self.in_progress_handshakes)
            self.in_progress_handshakes[client_id] = ServerHandshake(
                client_id,
                self.opts
            )

        session_handshake = self.in_progress_handshakes[client_id]
        response = session_handshake.process(load)
        if 'result' in response:
            transport.session['opposite_cert'] = session_handshake.client_certificate.as_pem()
            log.debug('Removing handshake session {client_id}'.format(client_id=client_id))
            self.in_progress_handshakes.pop(client_id)
            if response['result'] == True:
                pubfn = os.path.join(self.opts['pki_dir'],
                    'minions',
                        load['id'])
                with open(pubfn, 'w+') as fp_:
                    fp_.write(load['pub'])
        return response

    def send_response(self, client_id, response):
        if 'result' in response:
            self.in_progress_handshakes.pop(client_id)

        return response

    def send_error(self, client_id, error):
        self.in_progress_handshakes.pop(client_id)
        return {
            'enc' : 'clear',
            'result' : False,
            'load' : {
                'error' : error
            }
        }

class X509CertificateValidator(object):
    '''
    Container for the x509 Certificate Authority.  This requires a patched
    version of M2Crypto to work, as current versions of M2Crypto do not
    expose all of the required Certificate verification functionality of
    OpenSSL.

    See the Pulp project for a patch to M2Crypto-0.21.1 here:
    https://github.com/pulp/pulp/blob/master/deps/m2crypto/m2crypto-0.21.1-x509_crl.patch
    '''
    def __init__(self, opts):
        self.opts = opts
        if 'x509' in opts:
            # Create the Store for our Root CA Certificate
            self.ca_cert = self.opts['x509']['ca_cert']

            self.issuer_dn_match = None
            if 'issuer_dn_match' in opts['x509']:
                self.issuer_dn_match = re.compile(
                    opts['x509']['issuer_dn_match']
                )

            self.subject_dn_match = None
            if 'subject_dn_match' in opts['x509']:
                self.subject_dn_match = re.compile(
                    opts['x509']['subject_dn_match']
                )


def encrypt_with_public_key(rsa, message):
    block_length = len(rsa) / 8 - 42
    def encrypt(message, rsa):
        if message:
            head, tail = (message[:block_length], message[block_length:])
            return rsa.public_encrypt(head, RSA.pkcs1_oaep_padding) + encrypt(tail, rsa)
        else:
            return b""
    return encrypt(message, rsa)


def decrypt_with_private_key(rsa, message):
    block_length = len(rsa) / 8
    def decrypt(message, rsa):
        if message:
            head, tail = (message[:block_length], message[block_length:])
            return rsa.private_decrypt(head, RSA.pkcs1_oaep_padding) + decrypt(tail, rsa)
        else:
            return b""
    return decrypt(message, rsa)
