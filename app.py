import paramiko
import os, time, json
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
ssh_private_key_path = 'keys/id_new'

# Assuming you have the passphrase stored in a variable
passphrase = "Faisal"

# Load the encrypted OpenSSH private key using the passphrase
available_servers = [
    {
        "ssh_hostname": '68.183.89.111',
        "ssh_port": 22,  # Default SSH port
        "ssh_username": 'root',
        "label":"India/Singapore"
    },
    {
            "ssh_hostname": '104.236.70.46',
            "ssh_port": 22,  # Default SSH port
            "ssh_username": 'root',
            "label":"U.S/New York"
    },
    ]

# SSH Configuration Parameters
ssh_hostname = '68.183.89.111'
ssh_port = 22  # Default SSH port
ssh_username = 'root'

# WireGuard Configuration Parameters
wg_interface = 'wg0'
client_ip = '10.66.66.3'  # Example client IP
server_public_key = 'YaXOX3+2elhMVGmAubc77v4MslEMMIg6d3mpwSgITUM='
server_ip = '68.183.89.111:51820'  # Server IP and port
dns = '1.1.1.1'  # DNS server

# Paths
wg_conf_dir = '/etc/wireguard'
client_conf_dir = 'configs'  # Where to save client configs locally

def ssh_connect(hostname, port, username, key_path):
    """Establish an SSH connection to the server."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Assuming the key is not passphrase-protected
        key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
    except paramiko.ssh_exception.SSHException as e:
        print(f"Error loading the private key: {e}")
        raise

    try:
        client.connect(hostname, port, username, pkey=key)
    except Exception as e:
        print(f"Error connecting to the server: {e}")
        raise

    return client

def generate_keys_via_ssh(ssh_client):
    """Generate keys on the server using SSH."""
    stdin, stdout, stderr = ssh_client.exec_command('wg genkey')
    priv_key = stdout.read().decode().strip()
    stdin, stdout, stderr = ssh_client.exec_command(f'echo {priv_key} | wg pubkey')
    pub_key = stdout.read().decode().strip()
    return priv_key, pub_key

def create_client_config(ssh_client, client_ip, priv_key, pub_key, preshared_key):
    """Create a WireGuard configuration file and download it."""
    client_config = f"""
[Interface]
PrivateKey = {priv_key}
Address = {client_ip}/32, fc10:253::{client_ip.split('.')[-1]}/128  # Assuming last octet for IPv6
DNS = 10.2.53.1, fc10:253::1

[Peer]
PublicKey = {server_public_key}
PresharedKey = {preshared_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_ip}
"""

    # save configs in json file too


    config_filename = f"{wg_interface}-{client_ip}.conf"
    local_config_path = os.path.join(client_conf_dir, config_filename)
    remote_config_path = f"/tmp/{config_filename}"
    with open(local_config_path, 'w') as file:
        file.write(client_config.strip())

    client_config_json = {
        "interface": {
            "PrivateKey": priv_key,
            "Address": f"{client_ip}/32",
            "DNS": dns
        },
        "peer": {
            "PublicKey": server_public_key,
            "AllowedIPs": "0.0.0.0/0, ::/0",
            "PresharedKey": preshared_key,
            "Endpoint": server_ip
        }
    }

    client_config_json_string = json.dumps(client_config_json, indent=4)

    with open(f"{client_conf_dir}/{wg_interface}-{client_ip}.json", 'w') as file:
        file.write(client_config_json_string)

    # Upload the config file to the server
    ftp_client = ssh_client.open_sftp()
    ftp_client.put(local_config_path, remote_config_path)
    ftp_client.close()

    return local_config_path, remote_config_path, client_config_json

def generate_preshared_key_via_ssh(ssh_client):
    """Generate a preshared key."""
    stdin, stdout, stderr = ssh_client.exec_command('wg genpsk')
    return stdout.read().decode().strip()

def update_server_config(ssh_client, pub_key, client_ip):
    """Update the server configuration remotely via SSH."""
    peer_config = f"""
[Peer]
PublicKey = {pub_key}
AllowedIPs = {client_ip}/32
"""
    command = f'echo "{peer_config}" >> {wg_conf_dir}/{wg_interface}.conf'
    ssh_client.exec_command(command)

def restart_wireguard_interface(ssh_client, interface):
    """Restart the WireGuard interface to apply configuration changes."""
    # Bring the WireGuard interface down
    print("before downing")
    ssh_client.exec_command(f'wg-quick down {interface}')
    print("before uping")
    # Wait for the interface to go down
    time.sleep(1)  # Adjust the sleep time as necessary
    # Bring the WireGuard interface back up

    ssh_client.exec_command(f'wg-quick up {interface}')


def create_unique_ip():
    """Create a unique IP address for the client."""
    # Assuming the server's subnet is /24
    # This function can be modified to suit your network configuration
    used_ips = []

    # get list from useips.txt
    with open('usedips.txt', 'r') as file:
        used_ips = file.read().splitlines()

    for i in range(2, 255):
        ip = f'10.66.66.{i}'
        if ip not in used_ips:
            with open('usedips.txt', 'a') as file:
                file.write(ip + '\n')
            return ip


def main(server):

    try:
        local_ssh_hostname = available_servers[int(server)]['ssh_hostname']
        local_ssh_port = available_servers[int(server)]['ssh_port']
        local_ssh_username = available_servers[int(server)]['ssh_username']
        print("Creating WireGuard client configuration...")
        ssh_client = ssh_connect(local_ssh_hostname, local_ssh_port, local_ssh_username, ssh_private_key_path)
        print("SSH connection established.")

        client_ip = create_unique_ip()

        print(f"Client IP: {client_ip}")

        priv_key, pub_key = generate_keys_via_ssh(ssh_client)
        print("Keys generated.")
        preshared_key  = generate_preshared_key_via_ssh(ssh_client)
        print("Preshared key generated.")
        local_config_path, remote_config_path, res_json = create_client_config(ssh_client, client_ip, priv_key, pub_key, preshared_key)
        print("Client configuration created.")
        update_server_config(ssh_client, pub_key, client_ip)
        print("Server configuration updated.")

        restart_wireguard_interface(ssh_client, wg_interface)
        print("WireGuard interface restarted.")
        print(f"Client configuration created and uploaded at: {remote_config_path}")

        print(f"Local copy of client configuration: {local_config_path}")
        ssh_client.close()
        return True,res_json
    except Exception:
        return False,{}


@app.route('/health')
def health():
    return "OK", 200
@app.route('/get-servers')
def get_servers():
    only_names = []

    for i in range(len(available_servers)):
        only_names.append(available_servers[i]['label'])
    return jsonify(only_names), 200


@app.route('/create-client',methods=['POST'])
def create_client():
    if request.method == 'POST':
        data = request.get_json(silent=True)
        # client_id = data.get("client_id")
        token = data.get("token")

        if token != '123456lol':
            return jsonify({}), 400


        query_parameters = request.args
        body = request.get_json()

        print(body)

        print(query_parameters)
        server = query_parameters.get('server')
        return "done"


        done,res = main(server)
        if done:

            return jsonify(res), 200
        else:
            return json({}), 400

# if __name__ == "__main__":
#     port = int(8000)  # Default to 5000 if PORT not set
#     app.run(host='0.0.0.0', port=port)
