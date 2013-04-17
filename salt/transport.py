import logging
import sys
import time
import salt.tls_auth
import salt.crypt
import salt.payload

log = logging.getLogger(__name__)

class Transport(object):
    def __init__(self, opts):
        self.opts = opts
        self.session = {}

    def get_auth(self):
        if "x509" in self.opts:
            return salt.tls_auth.Auth(self, self.opts)
        else:
            return salt.crypt.Auth(self, self.opts)

    def sign_in(self):
        '''
        Authenticate with the master, this method breaks the functional
        paradigm, it will update the master information from a fresh sign
        in, signing in can occur as often as needed to keep up with the
        revolving master aes key.
        '''
        log.debug(
            'Attempting to authenticate with the Salt Master at {0}'.format(
                self.opts['master_ip']
            )
        )
        auth = self.get_auth()
        while True:
            result = auth.sign_in()
            if result != 'retry':
                log.info('Authentication with master successful!')
                break
            log.info('Waiting for minion key to be accepted by the master.')
            time.sleep(self.opts['acceptance_wait_time'])

    def get_crypticle(self):
        if "x509" in self.opts:
            return salt.tls_auth.Crypticle(self, self.opts)
        else:
            return salt.crypt.Crypticle(self.opts, self.session['aes'])

    def get_sreq(self):
        return salt.payload.SREQ(self.opts['master_uri'])

    def send_encrypted(self, load, tries=1, timeout=60):
        return self.get_sreq().send("encrypted", self.get_crypticle().dumps(load), tries, timeout)

    def sign_in_once_if_caller(self):
        '''
        Authenticate with the master, this method breaks the functional
        paradigm, it will update the master information from a fresh sign
        in, signing in can occur as often as needed to keep up with the
        revolving master aes key.
        '''
        while True:
            creds = self.sign_in()
            if creds == 'retry':
                if self.opts.get('caller'):
                    msg = ('Minion failed to authenticate with the master, '
                           'has the minion key been accepted?')
                    print(msg)
                    sys.exit(2)
                continue
            break