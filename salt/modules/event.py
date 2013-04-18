'''
Fire events on the minion, events can be fired up to the master
'''

# Import salt libs
import salt.transport
import salt.utils.event
import salt.payload


def fire_master(data, tag):
    '''
    Fire an event off on the master server

    CLI Example::

        salt '*' event.fire_master 'stuff to be in the event' 'tag'
    '''
    load = {'id': __opts__['id'],
            'tag': tag,
            'data': data,
            'cmd': '_minion_event'}
    transport = salt.transport.Transport(__opts__)
    transport.sign_in_once_if_caller()
    try:
        transport.send_encrypted(load)
    except Exception:
        pass
    return True


def fire(data, tag):
    '''
    Fire an event on the local minion event bus

    CLI Example::

        salt '*' event.fire 'stuff to be in the event' 'tag'
    '''
    return salt.utils.event.MinionEvent(**__opts__).fire_event(data, tag)
