#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstack-file
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstack-file.

    Blockstack-file is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstack-file is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstack-file. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import tempfile
import argparse
import socket
import json
import traceback

from ConfigParser import SafeConfigParser
from .version import __version__

import blockstack_client
import blockstack_gpg

APP_NAME = "files"
MAX_EXPIRED_KEYS = 20

log = blockstack_client.get_logger()

if os.environ.get("BLOCKSTACK_TEST", "") == "1":
    # testing!
    CONFIG_PATH = os.environ.get("BLOCKSTACK_FILE_CONFIG", None)
    assert CONFIG_PATH is not None, "BLOCKSTACK_FILE_CONFIG must be defined"

    CONFIG_DIR = os.path.dirname( CONFIG_PATH )

else:
    CONFIG_DIR = os.path.expanduser("~/.blockstack-files")
    CONFIG_PATH = os.path.join( CONFIG_DIR, "blockstack-files.ini" )

CONFIG_FIELDS = [
    'immutable_key',
    'key_id',
    'blockchain_id',
    'hostname',
    'wallet'
]

def get_config( config_path=CONFIG_PATH ):
    """
    Get the config
    """
   
    parser = SafeConfigParser()
    parser.read( config_path )

    config_dir = os.path.dirname(config_path)

    immutable_key = False
    key_id = None
    blockchain_id = None
    hostname = socket.gethostname()
    wallet = None
 
    if parser.has_section('blockstack-file'):

        if parser.has_option('blockstack-file', 'immutable_key'):
            immutable_key = parser.get('blockstack-file', 'immutable_key')
            if immutable_key.lower() in ['1', 'yes', 'true']:
                immutable_key = True
            else:
                immutable_key = False

        if parser.has_option('blockstack-file', 'file_id'):
            key_id = parser.get('blockstack-file', 'key_id' )

        if parser.has_option('blockstack-file', 'blockchain_id'):
            blockchain_id = parser.get('blockstack-file', 'blockchain_id')

        if parser.has_option('blockstack-file', 'hostname'):
            hostname = parser.get('blockstack-file', 'hostname')

        if parser.has_option('blockstack-file', 'wallet'):
            wallet = parser.get('blockstack-file', 'wallet')
        
    config = {
        'immutable_key': immutable_key,
        'key_id': key_id,
        'blockchain_id': blockchain_id,
        'hostname': hostname,
        'wallet': wallet
    }

    return config


def file_url_expired_keys( blockchain_id ):
    """
    Make a URL to the expired key list
    """
    url = blockstack_client.make_mutable_data_url( blockchain_id, "%s-old" % APP_NAME, None )
    return url


def file_fq_data_name( data_name ):
    """
    Make a fully-qualified data name
    """
    return "%s:%s" % (APP_NAME, data_name)


def file_is_fq_data_name( data_name ):
    """
    Is this a fully-qualified data name?
    """
    return data_name.startswith("%s:" % APP_NAME)


def file_data_name( fq_data_name ):
    """
    Get the relative name of this data from its fully-qualified name
    """
    assert file_is_fq_data_name( fq_data_name )
    return data_name[len("%s:" % APP_NAME):]


def file_key_lookup( blockchain_id, index, hostname, key_id=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Get the file-encryption GPG key for the given blockchain ID, by index.

    if index == 0, then give back the current key
    if index > 0, then give back an older (revoked) key.
    if key_id is given, index and hostname will be ignored

    Return {'status': True, 'key_data': ..., 'key_id': key_id, OPTIONAL['stale_key_index': idx]} on success
    Return {'error': ...} on failure
    """

    log.debug("lookup '%s' key for %s (index %s, key_id = %s)" % (hostname, blockchain_id, index, key_id))
    conf = get_config( config_path )
    config_dir = os.path.dirname(config_path)
    
    proxy = blockstack_client.get_default_proxy( config_path=config_path )
    immutable = conf['immutable_key']

    if key_id is not None:
        # we know exactly which key to get 
        # try each current key 
        hosts_listing = file_list_hosts( blockchain_id, wallet_keys=wallet_keys, config_path=config_path )
        if 'error' in hosts_listing:
            log.error("Failed to list hosts for %s: %s" % (blockchain_id, hosts_listing['error']))
            return {'error': 'Failed to look up hosts'}

        hosts = hosts_listing['hosts']
        for hostname in hosts:
            file_key = blockstack_gpg.gpg_app_get_key( blockchain_id, APP_NAME, hostname, immutable=immutable, key_id=key_id, config_dir=config_dir )
            if 'error' not in file_key:
                if key_id == file_key['key_id']:
                    # success!
                    return file_key

        # check previous keys...
        url = file_url_expired_keys( blockchain_id )
        old_key_bundle_res = blockstack_client.data_get( url, wallet_keys=wallet_keys, proxy=proxy )
        if 'error' in old_key_bundle_res:
            return old_key_bundle_res

        old_key_list = old_key_bundle_res['data']['old_keys']
        for i in xrange(0, len(old_key_list)):
            old_key = old_key_list[i]
            if old_key['key_id'] == key_id:
                # success!
                ret = {}
                ret.update( old_key )
                ret['stale_key_index'] = i+1 
                return old_key

        return {'error': 'No such key %s' % key_id}

    elif index == 0:
        file_key = blockstack_gpg.gpg_app_get_key( blockchain_id, APP_NAME, hostname, immutable=immutable, key_id=key_id, config_dir=config_dir )
        if 'error' in file_key:
            return file_key

        return file_key
    
    else:
        # get the bundle of revoked keys
        url = file_url_expired_keys( blockchain_id )
        old_key_bundle_res = blockstack_client.data_get( url, wallet_keys=wallet_keys, proxy=proxy )
        if 'error' in old_key_bundle_res:
            return old_key_bundle_res

        old_key_list = old_key_bundle_res['data']['old_keys']
        if index >= len(old_key_list)+1:
            return {'error': 'Index out of bounds: %s' % index}

        return old_key_list[index-1]


def file_key_retire( blockchain_id, file_key, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Retire the given key.  Move it to the head of the old key bundle list
    @file_key should be data returned by file_key_lookup
    Return {'status': True} on success
    Return {'error': ...} on error
    """

    config_dir = os.path.dirname(config_path)
    url = file_url_expired_keys( blockchain_id )
    proxy = blockstack_client.get_default_proxy( config_path=config_path )
        
    old_key_bundle_res = blockstack_client.data_get( url, wallet_keys=wallet_keys, proxy=proxy )
    if 'error' in old_key_bundle_res:
        log.warn('Failed to get old key bundle: %s' % old_key_bundle_res['error'])
        old_key_list = []

    else:
        old_key_list = old_key_bundle_res['data']['old_keys']
        for old_key in old_key_list:
            if old_key['key_id'] == file_key['key_id']:
                # already present 
                log.warning("Key %s is already retired" % file_key['key_id'])
                return {'status': True}

    old_key_list.insert(0, file_key )

    res = blockstack_client.data_put( url, {'old_keys': old_key_list}, wallet_keys=wallet_keys, proxy=proxy )
    if 'error' in res:
        log.error("Failed to append to expired key bundle: %s" % res['error'])
        return {'error': 'Failed to append to expired key list'}

    return {'status': True}


def file_key_regenerate( blockchain_id, hostname, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Generate a new encryption key.
    Retire the existing key, if it exists.
    Return {'status': True} on success
    Return {'error': ...} on error
    """
    
    config_dir = os.path.dirname(config_path)
    current_key = file_key_lookup( blockchain_id, 0, hostname, config_path=config_path )
    if 'status' in current_key and current_key['status']:
        # retire
        # NOTE: implicitly depends on this method failing only because the key doesn't exist
        res = file_key_retire( blockchain_id, current_key, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in res:
            log.error("Failed to retire key %s: %s" % (current_key['key_id'], res['error']))
            return {'error': 'Failed to retire key'}

    # make a new key 
    res = blockstack_gpg.gpg_app_create_key( blockchain_id, "files", hostname, wallet_keys=wallet_keys, config_dir=config_dir )
    if 'error' in res:
        log.error("Failed to generate new key: %s" % res['error'])
        return {'error': 'Failed to generate new key'}

    return {'status': True}


def file_encrypt( blockchain_id, hostname, recipient_blockchain_id_and_hosts, input_path, output_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Encrypt a file for a set of recipients.
    @recipient_blockchain_id_and_hosts must contain a list of (blockchain_id, hostname)
    Return {'status': True, 'sender_key_id': ...} on success, and write ciphertext to output_path
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)

    # find our encryption key
    key_info = file_key_lookup( blockchain_id, 0, hostname, config_path=config_path, wallet_keys=wallet_keys )
    if 'error' in key_info:
        return {'error': 'Failed to lookup encryption key'}

    # find the encryption key IDs for the recipients 
    recipient_keys = []
    for (recipient_id, recipient_hostname) in recipient_blockchain_id_and_hosts:
        if recipient_id == blockchain_id and recipient_hostname == hostname:
            # already have it 
            recipient_keys.append(key_info)
            continue

        recipient_info = file_key_lookup( recipient_id, 0, recipient_hostname, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in recipient_info:
            return {'error': "Failed to look up key for '%s'" % recipient_id}

        recipient_keys.append(recipient_info)

    # encrypt
    res = None
    with open(input_path, "r") as f:
        res = blockstack_gpg.gpg_encrypt( f, output_path, key_info, recipient_keys, passphrase=passphrase, config_dir=config_dir )
        
    if 'error' in res:
        log.error("Failed to encrypt: %s" % res['error'])
        return {'error': 'Failed to encrypt'}

    return {'status': True, 'sender_key_id': key_info['key_id']}


def file_decrypt_from_key_info( sender_key_info, blockchain_id, key_index, hostname, input_path, output_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Try to decrypt data with one of the receiver's keys
    Return {'status': True} if we succeeded
    Return {'error': ..., 'status': False} if we failed permanently
    Return {'error': ..., 'status': True} if the key failed, and we should try the next one.
    """
    config_dir = os.path.dirname(config_path)

    # find remote sender
    my_key_info = file_key_lookup( blockchain_id, key_index, hostname, config_path=config_path, wallet_keys=wallet_keys )
    if 'error' in my_key_info:
        log.error("Failed to look up key: %s" % my_key_info['error'])
        return {'status': True, 'error': 'Failed to lookup sender key'}

    # decrypt
    res = None 
    with open(input_path, "r") as f:
        res = blockstack_gpg.gpg_decrypt( f, output_path, sender_key_info, my_key_info, passphrase=passphrase, config_dir=config_dir )

    if 'error' in res:
        if res['error'] == 'Failed to decrypt data':
            log.warn("Key %s failed to decrypt" % my_key_info['key_id'])
            return {'status': True, 'error': 'Failed to decrypt with key'}

        else:
            log.error("Failed to decrypt: %s" % res['error'])
            return {'status': False, 'error': 'GPG error (%s)' % res['error']}

    return {'status': True}


def file_decrypt( blockchain_id, hostname, sender_blockchain_id, sender_key_id, input_path, output_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Decrypt a file from a sender's blockchain ID.
    Try our current key, and then the old keys
    (but warn if there are revoked keys)
    Return {'status': True} on success, and write plaintext to output_path
    Return {'error': ...} on failure
    """
    config_dir = os.path.dirname(config_path)
    decrypted = False
    old_key = False
    old_key_index = 0
    sender_old_key_index = 0

    # get the sender key 
    sender_key_info = file_key_lookup( sender_blockchain_id, None, None, key_id=sender_key_id, config_path=config_path, wallet_keys=wallet_keys ) 
    if 'error' in sender_key_info:
        log.error("Failed to look up sender key: %s" % sender_key_info['error'])
        return {'error': 'Failed to lookup sender key'}

    if 'stale_key_index' in sender_key_info.keys():
        old_key = True
        sender_old_key_index = sender_key_info['sender_key_index']

    # try each of our keys
    # current key...
    key_info = file_key_lookup( blockchain_id, 0, hostname, config_path=config_path, wallet_keys=wallet_keys )
    if 'error' not in key_info:
        res = file_decrypt_from_key_info( sender_key_info, blockchain_id, 0, hostname, input_path, output_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet_keys )
        if 'error' in res:
            if not res['status']:
                # permanent failure 
                log.error("Failed to decrypt: %s" % res['error'])
                return {'error': 'Failed to decrypt'}

        else:
            decrypted = True

    else:
        # did not look up key 
        log.error("Failed to lookup key: %s" % key_info['error'])

    if not decrypted:
        # try old keys 
        for i in xrange(1, MAX_EXPIRED_KEYS):
            res = file_decrypt_from_key_info( sender_key_info, blockchain_id, i, hostname, input_path, output_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet_keys )
            if 'error' in res:
                # key is not online, but don't try again 
                log.error("Failed to decrypt: %s" % res['error'])
                return {'error': 'Failed to decrypt'}
            else:
                decrypted = True
                old_key = True
                old_key_index = i
                break

    if decrypted:
        log.debug("Decrypted with %s.%s" % (blockchain_id, hostname))

        ret = {'status': True}
        if old_key:
            ret['warning'] = "Used stale key"
            ret['stale_key_index'] = old_key_index
            ret['stale_sender_key_index'] = sender_old_key_index

        return ret

    else:
        return {'error': 'No keys could decrypt'}


def file_sign( blockchain_id, hostname, input_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Sign a file with the current blockchain ID's host's public key.
    @config_path should be for the *client*, not blockstack-file
    Return {'status': True, 'sender_key_id': ..., 'sig': ...} on success, and write ciphertext to output_path
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)

    # find our encryption key
    key_info = file_key_lookup( blockchain_id, 0, hostname, config_path=config_path, wallet_keys=wallet_keys )
    if 'error' in key_info:
        return {'error': 'Failed to lookup encryption key'}

    # sign
    res = blockstack_gpg.gpg_sign( input_path, key_info, config_dir=config_dir )
    if 'error' in res:
        log.error("Failed to encrypt: %s" % res['error'])
        return {'error': 'Failed to encrypt'}

    return {'status': True, 'sender_key_id': key_info['key_id'], 'sig': res['sig']}


def file_verify( sender_blockchain_id, sender_key_id, input_path, sig, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Verify that a file was signed with the given blockchain ID
    @config_path should be for the *client*, not blockstack-file
    Return {'status': True} on succes
    Return {'error': ...} on error
    """
    config_dir = os.path.dirname(config_path)
    old_key = False
    old_key_index = 0
    sender_old_key_index = 0

    # get the sender key 
    sender_key_info = file_key_lookup( sender_blockchain_id, None, None, key_id=sender_key_id, config_path=config_path, wallet_keys=wallet_keys ) 
    if 'error' in sender_key_info:
        log.error("Failed to look up sender key: %s" % sender_key_info['error'])
        return {'error': 'Failed to lookup sender key'}

    if 'stale_key_index' in sender_key_info.keys():
        old_key = True
        sender_old_key_index = sender_key_info['sender_key_index']

    # attempt to verify 
    res = blockstack_gpg.gpg_verify( input_path, sig, sender_key_info, config_dir=config_dir )
    if 'error' in res:
        log.error("Failed to verify from %s.%s" % (sender_blockchain_id, sender_key_id))
        return {'error': 'Failed to verify'}

    return {'status': True}


def file_list_hosts( blockchain_id, wallet_keys=None, config_path=CONFIG_PATH ):
    """
    Given a blockchain ID, find out the hosts the blockchain ID owner has registered keys for.
    Return {'status': True, 'hosts': hostnames} on success
    Return {'error': ...} on failure
    """
    config_dir = os.path.dirname(config_path)
    try:
        ret = blockstack_gpg.gpg_list_app_keys( blockchain_id, APP_NAME, wallet_keys=wallet_keys, config_dir=config_dir )
    except Exception, e:
        ret = {'error': traceback.format_exc(e)}

    if 'error' in ret:
        log.error("Failed to list app keys: %s" % ret['error'])
        return {'error': 'Failed to list app keys'}

    hosts = []
    for key_info in ret:
        hostname = key_info['keyName']
        hosts.append(hostname)

    return {'status': True, 'hosts': hosts}


def file_put( blockchain_id, hostname, recipient_blockchain_ids, data_name, input_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Send a file to the given recipient, encrypted and signed with the
    given blockchain ID.
    Allow each recipient to receive the data on each of their hosts.
    Return {'status': True} on success, and upload to cloud storage
    Return {'error': ...} on error
    """
    fd, output_path = tempfile.mkstemp( prefix="blockstack-file-" )
    os.fchmod( fd, 0600 )
    os.close(fd)

    config_dir = os.path.dirname(config_path)
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )

    all_recipients = []
    
    # make available to all other hosts for this blockchain_id
    my_hosts = file_list_hosts( blockchain_id, wallet_keys=wallet_keys, config_path=config_path )
    if 'error' in my_hosts:
        log.error("Failed to list hosts: %s" % my_hosts['error'])
        os.unlink(output_path)
        return {'error': 'Failed to look up sender keys'}

    if hostname in my_hosts:
        my_hosts.remove(hostname)

    all_recipients += [(blockchain_id, host) for host in my_hosts['hosts']]

    # make available to all hosts for each recipient 
    for recipient_blockchain_id in recipient_blockchain_ids:
        their_hosts = file_list_hosts( recipient_blockchain_id, wallet_keys=wallet_keys, config_path=config_path )
        if 'error' in their_hosts:
            log.error("Failed to list hosts for %s: %s" % (recipient_blockchain_id, their_hosts['error']))
            os.unlink(output_path)
            return {'error': 'Failed to look up recipient keys'}

        all_recipients += [(recipient_blockchain_id, host) for host in their_hosts['hosts']]

    # encrypt
    res = file_encrypt( blockchain_id, hostname, all_recipients, input_path, output_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet_keys )
    if 'error' in res:
        log.error("Failed to encrypt: %s" % res['error'])
        os.unlink(output_path)
        return {'error': 'Failed to encrypt'}

    # load up 
    with open(output_path, "r") as f:
        ciphertext = f.read()

    message = {'ciphertext': ciphertext, 'sender_key_id': res['sender_key_id']}

    # put to mutable storage 
    fq_data_name = file_fq_data_name( data_name ) 
    proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    res = blockstack_client.data_put( blockstack_client.make_mutable_data_url( blockchain_id, fq_data_name, None ), message, wallet_keys=wallet_keys, proxy=proxy )
    if 'error' in res:
        log.error("Failed to put data: %s" % res['error'])
        os.unlink(output_path)
        return {'error': 'Failed to replicate data'}

    os.unlink(output_path)
    return {'status': True}


def file_get( blockchain_id, hostname, sender_blockchain_id, data_name, output_path, passphrase=None, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Get a file from a known sender.
    Store it to output_path
    Return {'status': True} on success
    Return {'error': error} on failure
    """
  
    config_dir = os.path.dirname(config_path)
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )
    proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    # get the ciphertext
    fq_data_name = file_fq_data_name( data_name ) 
    res = blockstack_client.data_get( blockstack_client.make_mutable_data_url( sender_blockchain_id, fq_data_name, None ), wallet_keys=wallet_keys, proxy=proxy )
    if 'error' in res:
        log.error("Failed to get ciphertext for %s: %s" % (fq_data_name, res['error']))
        return {'error': 'Failed to get encrypted file'}

    # stash
    fd, path = tempfile.mkstemp( prefix="blockstack-file-" )
    f = os.fdopen(fd, "w")
    f.write( res['data']['ciphertext'] )
    f.flush()
    os.fsync(f.fileno())
    f.close()

    sender_key_id = res['data']['sender_key_id']

    # decrypt it
    res = file_decrypt( blockchain_id, hostname, sender_blockchain_id, sender_key_id, path, output_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet_keys )
    os.unlink( path )
    if 'error' in res:
        log.error("Failed to decrypt: %s" % res['error'])
        return {'error': 'Failed to decrypt data'}

    else:
        # success!
        return res


def file_delete( blockchain_id, data_name, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    Remove a file
    Return {'status': True} on success
    Return {'error': error} on failure
    """

    config_dir = os.path.dirname(config_path)
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )
    proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    fq_data_name = file_fq_data_name( data_name ) 
    res = blockstack_client.data_delete( blockstack_client.make_mutable_data_url( blockchain_id, fq_data_name, None ), proxy=proxy, wallet_keys=wallet_keys )
    if 'error' in res:
        log.error("Failed to delete: %s" % res['error'])
        return {'error': 'Failed to delete'}

    return {'status': True}


def file_list( blockchain_id, config_path=CONFIG_PATH, wallet_keys=None ):
    """
    List all files uploaded to a particular blockchain ID
    Return {'status': True, 'listing': list} on success
    Return {'error': ...} on error
    """

    config_dir = os.path.dirname(config_path)
    client_config_path = os.path.join(config_dir, blockstack_client.CONFIG_FILENAME )
    proxy = blockstack_client.get_default_proxy( config_path=client_config_path )

    res = blockstack_client.data_list( blockchain_id, wallet_keys=wallet_keys, proxy=proxy )
    if 'error' in res:
        log.error("Failed to list data: %s" % res['error'])
        return {'error': 'Failed to list data'}

    listing = []

    # find the ones that this app put there 
    for rec in res['listing']:
        if not file_is_fq_data_name( rec['data_id'] ):
            continue
        
        listing.append( rec )

    return {'status': True, 'listing': listing}


def main():
    """
    Entry point for the CLI interface
    """
   
    argparser = argparse.ArgumentParser(
            description='Blockstack-file version {}'.format(__version__))

    subparsers = argparser.add_subparsers(
            dest='action', help='The file command to take [get/put/delete]')

    parser = subparsers.add_parser(
            'init',
            help='Initialize this host to start sending and receiving files')
    parser.add_argument(
            '--config', action='store',
            help='path to the config file to use (default is %s)' % CONFIG_PATH)
    parser.add_argument(
            '--blockchain_id', action='store',
            help='the recipient blockchain ID to use'),
    parser.add_argument(
            '--hostname', action='store',
            help='the recipient hostname to use')

    parser = subparsers.add_parser(
            'reset',
            help='Reset this host\'s key')
    parser.add_argument(
            '--config', action='store',
            help='path to the config file to use (default is %s)' % CONFIG_PATH)
    parser.add_argument(
            '--blockchain_id', action='store',
            help='the recipient blockchain ID to use'),
    parser.add_argument(
            '--hostname', action='store',
            help='the recipient hostname to use')

    parser = subparsers.add_parser(
            'get',
            help='Get a file')
    parser.add_argument(
            '--config', action='store',
            help='path to the config file to use (default is %s)' % CONFIG_PATH)
    parser.add_argument(
            '--blockchain_id', action='store',
            help='the recipient blockchain ID to use'),
    parser.add_argument(
            '--hostname', action='store',
            help='the recipient hostname to use')
    parser.add_argument(
            '--passphrase', action='store',
            help='decryption passphrase')
    parser.add_argument(
            '--wallet', action='store',
            help='path to your Blockstack wallet')
    parser.add_argument(
            'sender_blockchain_id', action='store',
            help='the sender\'s blockchain ID')
    parser.add_argument(
            'data_name', action='store',
            help='Public name of the file to fetch')
    parser.add_argument(
            'output_path', action='store', nargs='?',
            help='[optional] destination path to save the file; defaults to stdout')

    parser = subparsers.add_parser(
            'put',
            help='Share a file')
    parser.add_argument(
            '--config', action='store',
            help='path to the config file to use (default is %s)' % CONFIG_PATH)
    parser.add_argument(
            '--blockchain_id', action='store',
            help='the sender blockchain ID to use'),
    parser.add_argument(
            '--hostname', action='store',
            help='the sender hostname to use')
    parser.add_argument(
            '--passphrase', action='store',
            help='encryption passphrase')
    parser.add_argument(
            '--wallet', action='store',
            help='path to your Blockstack wallet')
    parser.add_argument(
            'input_path', action='store',
            help='Path to the file to share')
    parser.add_argument(
            'data_name', action='store',
            help='Public name of the file to store')
    # recipients come afterwards


    parser = subparsers.add_parser(
            'delete',
            help='Delete a shared file')
    parser.add_argument(
            '--config', action='store',
            help='path to the config file to use (default is %s)' % CONFIG_PATH)
    parser.add_argument(
            '--blockchain_id', action='store',
            help='the sender blockchain ID to use'),
    parser.add_argument(
            '--hostname', action='store',
            help='the sender hostname to use')
    parser.add_argument(
            '--wallet', action='store',
            help='path to your Blockstack wallet')
    parser.add_argument(
            'data_name', action='store',
            help='Public name of the file to delete')

    args, unparsed = argparser.parse_known_args()

    # load up config
    config_path = args.config
    if config_path is None:
        config_path = CONFIG_PATH

    conf = get_config( config_path )
    config_dir = os.path.dirname(config_path)
    blockchain_id = getattr(args, "blockchain_id", None)
    hostname = getattr(args, "hostname", None)
    passphrase = getattr(args, "passphrase", None)
    data_name = getattr(args, "data_name", None)
    wallet_path = getattr(args, "wallet", None)

    if blockchain_id is None:
        blockchain_id = conf['blockchain_id']

    if hostname is None:
        hostname = conf['hostname']

    if wallet_path is None:
        wallet_path = conf['wallet']
    
    if wallet_path is None and config_dir is not None:
        wallet_path = os.path.join(config_dir, blockstack_client.config.WALLET_FILENAME)

    # load wallet 
    if wallet_path is not None and os.path.exists( wallet_path ):
        # load from disk
        log.debug("Load wallet from %s" % wallet_path)
        wallet = blockstack_client.load_wallet( config_dir=config_dir, wallet_path=wallet_path, include_private=True )
        if 'error' in wallet:
            print >> sys.stderr, json.dumps(wallet, sort_keys=True, indent=4 )
            sys.exit(1)

        else:
            wallet = wallet['wallet']

    else:
        # load from RPC
        log.debug("Load wallet from RPC")
        wallet = blockstack_client.dump_wallet(config_path=config_path)
        if 'error' in wallet:
            print >> sys.stderr, json.dumps(wallet, sort_keys=True, indent=4)
            sys.exit(1)

    log.debug("Process %s" %  args.action)
    if args.action in ['init', 'reset']:
        # (re)key
        res = file_key_regenerate( blockchain_id, hostname, config_path=config_path, wallet_keys=wallet ) 
        if 'error' in res:
            print >> sys.stderr, json.dumps(res, sort_keys=True, indent=4 )
            sys.exit(1)
        

    if args.action == 'get':
        # get a file
        sender_blockchain_id = args.sender_blockchain_id
        output_path = args.output_path

        tmp = False
        if output_path is None:
            fd, path = tempfile.mkstemp( prefix='blockstack-file-', dir=config_dir )
            os.close(fd)
            output_path = path
            tmp = True

        res = file_get( blockchain_id, hostname, sender_blockchain_id, data_name, output_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet )
        if 'error' in res:
            print >> sys.stderr, json.dumps(res, sort_keys=True, indent=4 )
            sys.exit(1)

        if tmp:
            # print to stdout 
            with open(output_path, "r") as f:
                while True:
                    buf = f.read(65536)
                    if len(buf) == 0:
                        break

                    sys.stdout.write(buf)

            os.unlink(output_path)

    elif args.action == 'put':
        # put a file
        recipients = unparsed
        input_path = args.input_path
        res = file_put( blockchain_id, hostname, recipients, data_name, input_path, passphrase=passphrase, config_path=config_path, wallet_keys=wallet )
        if 'error' in res:
            print >> sys.stderr, json.dumps(res, sort_keys=True, indent=4 )
            sys.exit(1)

    elif args.action == 'delete':
        # delete a file
        res = file_delete( blockchain_id, data_name, config_path=config_path, wallet_keys=wallet )
        if 'error' in res:
            print >> sys.stderr, json.dumps(res, sort_keys=True, indent=4 )
            sys.exit(1)

    
    print >> sys.stderr, json.dumps({'status': True}, sort_keys=True, indent=4 )
    sys.exit(0)


