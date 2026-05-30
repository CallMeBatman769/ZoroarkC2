How to use:

1. Start the listener using the command "CStart < ip > < port >" where IP stands for the ip you want to listen for (default 0.0.0.0) and port for the port you wan't to listen on.

2. Wait for a client to connect. It will show in the command prompt with the text "[OK] NEW CONNECTION"

3. Get the id of the connected client using the command "Clients"

4. Copy the ID (In most cases it's just 1) send a payload using the command "send < clientid > < payload >" if you wan't to send a payload to all clients, use "send all < payload >" this will send the payload/command to all clients

5. Wait for the output

Functions:

- CStart < ip > < port > Starts the listener on the specified port and listens for the specified ip (0.0.0.0 is the default. Listens for every IP)

- Clients Lists every Client and the ID 

- cload < config > load the specified config. Used for visual stuff

- send < id|all > < payload > sends the specified command/payload to the specified ID. If you use send all it sends the payload to every client.

- exit Exits the program and clears the cmd

TO DO:

- Add beacon mode

- Add an export function to export the output