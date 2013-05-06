from _ctypes import Structure
from ctypes import c_char, c_long, c_byte
import fnmatch
import hashlib
import logging
import multiprocessing
import os
import re
import stat
import sys
import time
import uuid
from M2Crypto import RSA
import msgpack
import salt.tls_auth
import salt.tls_handshake
import salt.crypt
import salt.payload
import salt.utils.verify
import salt.utils.event

log = logging.getLogger(__name__)

class ClientTransport(object):
    def __init__(self, opts):
        self.opts = opts
        self.id = opts['id']
        self.session = SessionStore(2)

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

    def sign_in_once_if_caller(self):
        '''
        Authenticate with the master, this method breaks the functional
        paradigm, it will update the master information from a fresh sign
        in, signing in can occur as often as needed to keep up with the
        revolving master aes key.
        '''
        while True:
            creds = self.get_auth().sign_in()
            if creds == 'retry':
                if self.opts.get('caller'):
                    msg = ('Minion failed to authenticate with the master, '
                           'has the minion key been accepted?')
                    print(msg)
                    sys.exit(2)
                continue
            break

    def get_auth(self):
        if "x509" in self.opts:
            return salt.tls_auth.Auth(self, self.opts)
        else:
            return salt.crypt.Auth(self, self.opts)

    def get_crypticle(self, session_id='master'):
        if "x509" in self.opts:
            return salt.tls_auth.Crypticle(self, self.opts)
        else:
            return salt.crypt.Crypticle(self.opts, self, session_id)

    def get_sreq(self):
        return salt.payload.SREQ(self.opts['master_uri'])

    def send_encrypted(self, load, tries=1, timeout=60):
        crypticle = self.get_crypticle()
        return crypticle.loads(self.get_sreq().send("encrypted", crypticle.dumps(load), tries, timeout, sender_id=self.id))



class ServerTransport(object):
    def __init__(self, opts):
        self.opts = opts
        self.session = SessionStore()
        if not "x509" in self.opts and "aes" in self.opts:
            self.aes = self.opts['aes']
        self.event_obj = None
        self.master_key_obj = None
        self.tls_funcs = salt.tls_handshake.TLSFuncs(self.opts)

    @property
    def event(self):
        if not self.event_obj:
            self.event_obj = salt.utils.event.MasterEvent(self.opts['sock_dir'])
        return self.event_obj

    @property
    def master_key(self):
        if not self.master_key_obj:
            self.master_key_obj = salt.crypt.MasterKeys(self.opts)
        return self.master_key_obj

    def get_crypticle(self, session_id):
        if "x509" in self.opts:
            return salt.tls_auth.Crypticle(self, self.opts)
        else:
            return salt.crypt.Crypticle(self.opts, self, session_id)

    def auth(self, load, session_id):
        '''
        Authenticate the client, use the sent public key to encrypt the aes key
        which was generated at start up.

        This method fires an event over the master event manager. The event is
        tagged "auth" and returns a dict with information about the auth
        event
        '''
        # 0. Check for max open files
        # 1. Verify that the key we are receiving matches the stored key
        # 2. Store the key if it is not there
        # 3. make an rsa key with the pub key
        # 4. encrypt the aes key as an encrypted salt.payload
        # 5. package the return and return it

        salt.utils.verify.check_max_open_files(self.opts)

        log.info('Authentication request from {id}'.format(**load))
        if "x509" in self.opts:
            return self.tls_funcs._handshake(load, self)
        else:
            pubfn = os.path.join(self.opts['pki_dir'],
                    'minions',
                    load['id'])
            pubfn_pend = os.path.join(self.opts['pki_dir'],
                    'minions_pre',
                    load['id'])
            pubfn_rejected = os.path.join(self.opts['pki_dir'],
                    'minions_rejected',
                    load['id'])
            if self.opts['open_mode']:
                # open mode is turned on, nuts to checks and overwrite whatever
                # is there
                pass
            elif os.path.isfile(pubfn_rejected):
                # The key has been rejected, don't place it in pending
                log.info('Public key rejected for {id}'.format(**load))
                ret = {'enc': 'clear',
                       'load': {'ret': False}}
                eload = {'result': False,
                         'id': load['id'],
                         'pub': load['pub']}
                self.event.fire_event(eload, 'auth')
                return ret
            elif os.path.isfile(pubfn):
                # The key has been accepted check it
                if not salt.utils.fopen(pubfn, 'r').read() == load['pub']:
                    log.error(
                        'Authentication attempt from {id} failed, the public '
                        'keys did not match. This may be an attempt to compromise '
                        'the Salt cluster.'.format(**load)
                    )
                    ret = {'enc': 'clear',
                           'load': {'ret': False}}
                    eload = {'result': False,
                             'id': load['id'],
                             'pub': load['pub']}
                    self.event.fire_event(eload, 'auth')
                    return ret
            elif not os.path.isfile(pubfn_pend)\
                    and not self._check_autosign(load['id']):
                if os.path.isdir(pubfn_pend):
                    # The key path is a directory, error out
                    log.info(
                        'New public key id is a directory {id}'.format(**load)
                    )
                    ret = {'enc': 'clear',
                           'load': {'ret': False}}
                    eload = {'result': False,
                             'id': load['id'],
                             'pub': load['pub']}
                    self.event.fire_event(eload, 'auth')
                    return ret
                # This is a new key, stick it in pre
                log.info(
                    'New public key placed in pending for {id}'.format(**load)
                )
                with salt.utils.fopen(pubfn_pend, 'w+') as fp_:
                    fp_.write(load['pub'])
                ret = {'enc': 'clear',
                       'load': {'ret': True}}
                eload = {'result': True,
                         'act': 'pend',
                         'id': load['id'],
                         'pub': load['pub']}
                self.event.fire_event(eload, 'auth')
                return ret
            elif os.path.isfile(pubfn_pend)\
                    and not self._check_autosign(load['id']):
                # This key is in pending, if it is the same key ret True, else
                # ret False
                if not salt.utils.fopen(pubfn_pend, 'r').read() == load['pub']:
                    log.error(
                        'Authentication attempt from {id} failed, the public '
                        'keys in pending did not match. This may be an attempt to '
                        'compromise the Salt cluster.'.format(**load)
                    )
                    eload = {'result': False,
                             'id': load['id'],
                             'pub': load['pub']}
                    self.event.fire_event(eload, 'auth')
                    return {'enc': 'clear',
                            'load': {'ret': False}}
                else:
                    log.info(
                        'Authentication failed from host {id}, the key is in '
                        'pending and needs to be accepted with salt-key '
                        '-a {id}'.format(**load)
                    )
                    eload = {'result': True,
                             'act': 'pend',
                             'id': load['id'],
                             'pub': load['pub']}
                    self.event.fire_event(eload, 'auth')
                    return {'enc': 'clear',
                            'load': {'ret': True}}
            elif os.path.isfile(pubfn_pend)\
                    and self._check_autosign(load['id']):
                # This key is in pending, if it is the same key auto accept it
                if not salt.utils.fopen(pubfn_pend, 'r').read() == load['pub']:
                    log.error(
                        'Authentication attempt from {id} failed, the public '
                        'keys in pending did not match. This may be an attempt to '
                        'compromise the Salt cluster.'.format(**load)
                    )
                    eload = {'result': False,
                             'id': load['id'],
                             'pub': load['pub']}
                    self.event.fire_event(eload, 'auth')
                    return {'enc': 'clear',
                            'load': {'ret': False}}
                else:
                    pass
            elif not os.path.isfile(pubfn_pend)\
                    and self._check_autosign(load['id']):
                # This is a new key and it should be automatically be accepted
                pass
            else:
                # Something happened that I have not accounted for, FAIL!
                log.warn('Unaccounted for authentication failure')
                eload = {'result': False,
                         'id': load['id'],
                         'pub': load['pub']}
                self.event.fire_event(eload, 'auth')
                return {'enc': 'clear',
                        'load': {'ret': False}}

            log.info('Authentication accepted from {id}'.format(**load))
            with salt.utils.fopen(pubfn, 'w+') as fp_:
                fp_.write(load['pub'])
            pub = None

            # The key payload may sometimes be corrupt when using auto-accept
            # and an empty request comes in
            try:
                pub = RSA.load_pub_key(pubfn)
            except RSA.RSAError, err:
                log.error('Corrupt public key "{0}": {1}'.format(pubfn, err))
                return {'enc': 'clear',
                        'load': {'ret': False}}

            ret = {'enc': 'pub',
                   'pub_key': self.master_key.get_pub_str(),
                   'publish_port': self.opts['publish_port'],
                  }
            if self.opts['auth_mode'] >= 2:
                if 'token' in load:
                    try:
                        mtoken = self.master_key.key.private_decrypt(load['token'], 4)
                        aes = '{0}_|-{1}'.format(self.opts['aes'], mtoken)
                    except Exception:
                        # Token failed to decrypt, send back the salty bacon to
                        # support older minions
                        pass
                else:
                    aes = self.opts['aes']

                ret['aes'] = pub.public_encrypt(aes, 4)
            else:
                if 'token' in load:
                    try:
                        mtoken = self.master_key.key.private_decrypt(
                            load['token'], 4
                        )
                        ret['token'] = pub.public_encrypt(mtoken, 4)
                    except Exception:
                        # Token failed to decrypt, send back the salty bacon to
                        # support older minions
                        pass

                aes = self.opts['aes']
                ret['aes'] = pub.public_encrypt(self.opts['aes'], 4)
            # Be aggressive about the signature
            digest = hashlib.sha256(aes).hexdigest()
            ret['sig'] = self.master_key.key.private_encrypt(digest, 5)
            eload = {'result': True,
                     'act': 'accept',
                     'id': load['id'],
                     'pub': load['pub']}
            # Generate shared across all the minions key for publishing
            self.get_crypticle('publish')
            publish_key = self.session['publish']['aes']
            ret['publish_aes'] = pub.public_encrypt(publish_key, 4)
            publish_digest = hashlib.sha256(publish_key).hexdigest()
            ret['publish_sig'] = self.master_key.key.private_encrypt(publish_digest, 5)
            # Save session
            session = self.session[session_id]
            session['aes'] = aes
            self.session[session_id] = session

            self.event.fire_event(eload, 'auth')
            return ret

    def _check_autosign(self, keyid):
        '''
        Checks if the specified keyid should automatically be signed.
        '''

        if self.opts['auto_accept']:
            return True

        autosign_file = self.opts.get("autosign_file", None)

        if not autosign_file or not os.path.exists(autosign_file):
            return False

        if not self._check_permissions(autosign_file):
            message = "Wrong permissions for {0}, ignoring content"
            log.warn(message.format(autosign_file))
            return False

        with salt.utils.fopen(autosign_file, 'r') as fp_:
            for line in fp_:
                line = line.strip()

                if line.startswith('#'):
                    continue

                if line == keyid:
                    return True
                if fnmatch.fnmatch(keyid, line):
                    return True
                try:
                    if re.match(line, keyid):
                        return True
                except re.error:
                    log.warn(
                        '{0} is not a valid regular expression, ignoring line '
                        'in {1}'.format(
                            line, autosign_file
                        )
                    )
                    continue

        return False

    def _check_permissions(self, filename):
        '''
        check if the specified filename has correct permissions
        '''
        if 'os' in os.environ:
            if os.environ['os'].startswith('Windows'):
                return True

        import pwd  # after confirming not running Windows
        import grp
        try:
            user = self.opts['user']
            pwnam = pwd.getpwnam(user)
            uid = pwnam[2]
            gid = pwnam[3]
            groups = [g.gr_gid for g in grp.getgrall() if user in g.gr_mem]
        except KeyError:
            log.error(
                'Failed to determine groups for user {0}. The user is not '
                'available.\n'.format(
                    user
                )
            )
            return False

        fmode = os.stat(filename)

        if os.getuid() == 0:
            if fmode.st_uid == uid or not fmode.st_gid == gid:
                return True
            elif self.opts.get('permissive_pki_access', False) \
                    and fmode.st_gid in groups:
                return True
        else:
            if stat.S_IWOTH & fmode.st_mode:
                # don't allow others to write to the file
                return False

            # check group flags
            if self.opts.get('permissive_pki_access', False) \
              and stat.S_IWGRP & fmode.st_mode:
                return True
            elif stat.S_IWGRP & fmode.st_mode:
                return False

            # check if writable by group or other
            if not (stat.S_IWGRP & fmode.st_mode or
              stat.S_IWOTH & fmode.st_mode):
                return True

        return False

MAX_SESSION_SIZE=1000


def _timestamp():
    return int(round(time.time() * 1000))


class SessionStore(object):
    def __init__(self, capacity=1000):
        self.lock = multiprocessing.Lock()
        self.length = multiprocessing.Value("i", 0)
        self.memory = multiprocessing.Array(_Session, capacity, lock=False)

    def __len__(self):
        self.lock.acquire()
        try:
            return self.length.value
        finally:
            self.lock.release()

    def __getitem__(self, session_id):
        self.lock.acquire()
        try:
            i = 0
            while True:
                if i >= self.length.value:
                    break
                session = self.memory[i]
                if session.id == session_id:
                    if session.timestamp + 1000000 > _timestamp():
                        return Session(session.id, session.timestamp, session.session)
                i += 1
            session = Session(session_id, _timestamp(), msgpack.dumps({}))
            s = self.memory[self.length.value]
            s.id = session.session_id
            s.timestamp = session.timestamp
            s.session[0:] = bytearray(session.session).ljust(MAX_SESSION_SIZE, '\x00')
            self.length.value += 1
            return session
        finally:
            self.lock.release()

    def __setitem__(self, session_id, sess):
        self.lock.acquire()
        try:
            if session_id != sess.session_id:
                raise RuntimeError("Invalid arguments. session_id didn't match id of session object")
            if len(sess.session) > MAX_SESSION_SIZE:
                raise RuntimeError("Session dictionary size exceed limits")
            i = 0
            while True:
                if i >= self.length.value:
                    break
                session = self.memory[i]
                if session.id == session_id:
                    session.session[0:] = bytearray(sess.session).ljust(MAX_SESSION_SIZE, '\x00')
                    session.timestamp = sess.timestamp
                    return
                i += 1
            s = self.memory[self.length.value]
            s.id = sess.session_id
            s.timestamp = sess.timestamp
            s.session[0:] = bytearray(sess.session).ljust(MAX_SESSION_SIZE, '\x00')
            self.length.value += 1
        finally:
            self.lock.release()

    def clean(self):
        self.lock.acquire()
        try:
            now = _timestamp()
            i = 0
            while True:
                if i >= self.length.value:
                    break
                if self.memory[i].timestamp + 10000 > now:
                    self.memory[i:] = self.memory[i + 1:]
                    self.length.value -= 1
                else:
                    i += 1
        finally:
            self.lock.acquire()

    def __delitem__(self, key):
        raise NotImplementedError()

    def __contains__(self, item):
        self.lock.acquire()
        try:
            for session in self.memory:
                if session.id == item.session_id:
                    return True
            return False
        finally:
            self.lock.release()

    def __repr__(self):
        res = "("
        for i in range(0, self.length.value):
            session = self.memory[i]
            res += "%s" % Session(session.id, session.timestamp, session.session)
        res += ")"
        return res


class _Session(Structure):
    _fields_ = [('id', c_char * 512), ('timestamp', c_long), ('session', c_byte * MAX_SESSION_SIZE)]


class Session(object):
    def __init__(self, session_id=None, timestamp=None, session=None):
        if not session_id: session_id = uuid.uuid1().bytes
        if not timestamp: timestamp = _timestamp()
        if not session: session = {}
        self.session_id = session_id
        self.timestamp = timestamp
        if isinstance(session, dict):
            self.session_dict = session
        else:
            unpacker = msgpack.Unpacker()
            unpacker.feed(session)
            self.session_dict = unpacker.unpack()

    @property
    def session(self):
        return msgpack.dumps(self.session_dict)

    def __getitem__(self, key):
        return self.session_dict[key]

    def __setitem__(self, key, item):
        self.session_dict[key] = item

    def __contains__(self, key):
        return key in self.session_dict

    def __repr__(self):
        return "<Session id=%s timestamp=%s dict=%s>" % (self.session_id, self.timestamp, self.session_dict)