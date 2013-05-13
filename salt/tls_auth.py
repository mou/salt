import hashlib
import hmac
import logging
import os
from Crypto.Cipher import AES
from M2Crypto import X509, RSA, EVP
import salt.payload
import salt.tls_handshake
from salt.exceptions import SaltClientError, AuthenticationError

log = logging.getLogger(__name__)

class Auth(object):
    '''
    The Auth class provides the sequence for setting up communication with
    the master server from a minion.
    '''
    def __init__(self, transport, opts):
        self.opts = opts
        self.transport = transport
        self.serial = salt.payload.Serial(self.opts)
        self.pub_path = os.path.join(self.opts['pki_dir'], 'minion.pub')
        self.rsa_path = os.path.join(self.opts['pki_dir'], 'minion.pem')
        if 'syndic_master' in self.opts:
            self.mpub = 'syndic_master.pub'
        elif 'alert_master' in self.opts:
            self.mpub = 'monitor_master.pub'
        else:
            self.mpub = 'minion_master.pub'

    def get_private_key(self):
        key = RSA.load_key(self.opts['x509']['key'])
        return key

    def get_keys(self):
        '''
        Returns a key objects for the minion
        '''
        #TODO: Check for file and do error handling
        key = RSA.load_key(self.opts['x509']['key'])
        return key

    def sign_in(self, timeout, safe):
        '''
        Send a sign in request to the master, sets the key information and
        returns a dict containing the master publish interface to bind to
        and the decrypted aes key for transport decryption.
        '''
        auth = {}
        try:
            self.opts['master_ip'] = salt.utils.dns_check(
                    self.opts['master'],
                    True
                    )
        except SaltClientError:
            return 'retry'
        sreq = salt.payload.SREQ(
                self.opts['master_uri'],
                self.opts.get('id', '')
                )

        log.debug('Starting TLS..')
        payload = salt.tls_handshake.do_client_handshake(sreq, self.opts)
        session = self.transport.session['master']
        session['aes'] = payload['aes']
        session['publish_port'] = payload['publish_port']
        self.transport.session['master'] = session


class Crypticle(object):
    '''
    Authenticated encryption class

    Encryption algorithm: AES-CBC
    Signing algorithm: HMAC-SHA256
    '''

    PICKLE_PAD = 'pickle::'
    AES_BLOCK_SIZE = 16

    def __init__(self, transport, opts):
        self.key_path = opts['x509']['key']
        self.cert_path = opts['x509']['cert']
        self.opposite_cert_string = transport.session['opposite_cert']
        self.serial = salt.payload.Serial(opts)
        self.key_obj = None
        self.cert_obj = None
        self.opposite_cert_obj = None

    @classmethod
    def new_key(cls, key_size=192):
        key = os.urandom(key_size // 8)
        return key

    @property
    def key(self):
        if not self.key_obj:
            self.key_obj = RSA.load_key(self.key_path)
        return self.key_obj

    @property
    def cert(self):
        if not self.cert_obj:
            self.cert_obj = X509.load_cert(self.cert_path)
        return self.cert_obj

    @property
    def opposite_cert(self):
        if not self.opposite_cert_obj:
            self.opposite_cert_obj = X509.load_cert_string(self.opposite_cert_string)
        return self.opposite_cert_obj

    @property
    def opposite_pub_key(self):
        return self.opposite_cert.get_pubkey().get_rsa()

    def encrypt(self, data):
        '''
        encrypt data with AES-CBC and sign it with HMAC-SHA256
        '''
        aes_key = Crypticle.new_key()
        pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
        padded_data = data + pad * chr(pad)
        iv_bytes = os.urandom(self.AES_BLOCK_SIZE)
        cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
        sign = self.key.sign_rsassa_pss(self._hash(data + aes_key), 'sha1')
        encrypted_data = iv_bytes + cypher.encrypt(padded_data)
        encrypted_key = salt.tls_handshake.encrypt_with_public_key(self.opposite_pub_key, aes_key)
        return {"sign": sign,
                "encrypted_key": encrypted_key,
                "encrypted_data": encrypted_data}

    def decrypt(self, data):
        '''
        verify HMAC-SHA256 signature and decrypt data with AES-CBC
        '''
        sign = data['sign']
        encrypted_key = data['encrypted_key']
        encrypted = data['encrypted_data']
        aes_key = salt.tls_handshake.decrypt_with_private_key(self.key, encrypted_key)
        iv_bytes = encrypted[:self.AES_BLOCK_SIZE]
        data = encrypted[self.AES_BLOCK_SIZE:]
        cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
        padded_data = cypher.decrypt(data)
        data = padded_data[:-ord(padded_data[-1])]
        if not self.opposite_pub_key.verify_rsassa_pss(self._hash(data + aes_key), sign, 'sha1'):
            log.debug('Failed to authenticate message')
            raise AuthenticationError('message authentication failed')
        return data

    def dumps(self, obj):
        '''
        Serialize and encrypt a python object
        '''
        return self.encrypt(self.PICKLE_PAD + self.serial.dumps(obj))

    def loads(self, data):
        '''
        Decrypt and un-serialize a python object
        '''
        if data is None:
            return None
        data = self.decrypt(data)
        # simple integrity check to verify that we got meaningful data
        if not data.startswith(self.PICKLE_PAD):
            return {}
        return self.serial.loads(data[len(self.PICKLE_PAD):])

    def _hash(self, data):
        digester = EVP.MessageDigest('sha1')
        digester.update(data)
        return digester.digest()
