# IMPORTANT :star2:
Scroll down the Manual for detailed instructions to Run the Program. 

## SETUP
The Programs are pre-loaded with the Certificates made by @0r-gh0 so can just successfully run the program files with required libraries, without creating a new Certificate.

**If you want to Create Your Own Certificate then proceed with the following steps**

## Creating Environment
1. Clone/Download this Repository to your System
2. reate a Directory/Folder and Name it `OpenSSL`
3. Copy the Programs `SERVER_SSL.c` and `CLIENT_SSL.c`
4. In the Same Directory Open Terminal in Admin Mode
5. Admin Mode : `sudo su` and enter your credentials

## Install OpenSSL
Check for your [OpenSSL](https://www.openssl.org/) Version : 
```
openssl version
```

If not present then install it.
```
sudo apt-get install openssl
```

### Next Generate the Certificate Authority (CA) Private Key
```
openssl genpkey -algorithm RSA -out ca.key
```

### Create the CA Certificate
```
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt
```
You'll be prompted to enter information about your CA (country, state, organization, etc.).

### Example
```
Country Name (2 letter code) [AU]: IN
State or Province Name (full name) [Some-State]: West Bengal
Locality Name (eg, city) []: Kolkata
Organization Name (eg, company) [Internet Widgits Pty Ltd]: ISI Kolkata
Organizational Unit Name (eg, section) [] : Cryptology and Security
Common Name (e.g. server FQDN or YOUR name) []: ARGHA
Email Address []: arghacious@gmail.com
```

## Generate the Server Certificate

### Generate the Server Private Key
```
openssl genpkey -algorithm RSA -out server.key
```

### Create a Certificate Signing Request (CSR)
```
openssl req -new -key server.key -out server.csr
```
You'll be prompted to enter information about your CA (country, state, organization, etc.).

### Example
```
Country Name (2 letter code) [AU]: IN
State or Province Name (full name) [Some-State]: West Bengal
Locality Name (eg, city) []: Kolkata
Organization Name (eg, company) [Internet Widgits Pty Ltd]: ISI Kolkata
Organizational Unit Name (eg, section) [] : Cryptology and Security
Common Name (e.g. server FQDN or YOUR name) []: ARGHA
Email Address []: arghacious@gmail.com
```
```
Please enter the following 'extra' attributes to be sent with your certificate request
A challenge password []: ARGHA123
An optional company name []: ISIK
```
### Sign the server CSR with the CA certificate
```
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 500 -sha256
```

It will result into
```
Certificate request self-signature ok
subject=C=IN, ST=West Bengal, L=Kolkata, O=ISI Kolkata, OU=Cryptology and Security, CN=ARGHA, emailAddress=arghacious@gmail.com
```

### Generate the Client Certificate

## Generate the client private key
```
openssl genpkey -algorithm RSA -out client.key
```

## Create a Certificate Signing Request (CSR)
```
openssl req -new -key client.key -out client.csr
```
You'll be prompted to enter information about your CA (country, state, organization, etc.).

### Example
```
Country Name (2 letter code) [AU]: IN
State or Province Name (full name) [Some-State]: West Bengal
Locality Name (eg, city) []: Kolkata
Organization Name (eg, company) [Internet Widgits Pty Ltd]: ISI Kolkata
Organizational Unit Name (eg, section) [] : Cryptology and Security
Common Name (e.g. server FQDN or YOUR name) []: ARGHA
Email Address []: arghacious@gmail.com
```
```
Please enter the following 'extra' attributes to be sent with your certificate request
A challenge password []: ARGHA123
An optional company name []: ISIK
```
### Sign the Client CSR with the CA certificate
```
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 500 -sha256
```

It will result into
```
Certificate request self-signature ok
subject=C=IN, ST=West Bengal, L=Kolkata, O=ISI Kolkata, OU=Cryptology and Security, CN=ARGHA, emailAddress=arghacious@gmail.com
```

## Organize the Certificates

### Create a directory structure to store your certificates and keys
```
mkdir -p key
mv ca.crt key/
mv server.crt key/certificate.crt
mv server.key key/private_key.pem
mv client.crt key/
mv client.key key/
```
---

# Code Execution

## Update Your Code to Use the Certificates
Make sure your server and client code points to the correct paths for the certificates and keys:

### Server Side (update SERVER_SSL.c)
```
char CertFile[] = "key/certificate.crt";
char KeyFile[] = "key/private_key.pem";
```

### Client Side (update CLIENT_SSL.c)
```
char CertFile[] = "key/client.crt";
char KeyFile[] = "key/client.key";
```

**NOTE : SSLv3 Has been depreciated** 

*This Line :  `method = SSLv3_client_method()`; OR `SSLv3_client_method();`*

> If Using Manmatha Sir's Program 
> In Client Side function `SSL_CTX* InitCTX(void)` Replace with 
> `method = TLS_client_method();`
>
> In Server Side function `SSL_CTX* InitServerCTX(void)` Replace with 
> `method = TLS_server_method();`
>
> *Note : I have Updated Majorly in my Code So No Need to make any Change*

### Enter the Admin Mode
```
sudo su
```

### Check if this Library is installed.
```
sudo apt install libssl-dev
```

## Compile the Program 
```
gcc -o client CLIENT_SSL.c -lssl -lcrypto
gcc -o server SERVER_SSL.c -lssl -lcrypto
```

## Run the program in 2 different terminal windows with Client and Server
```
./client
./server
```

---

## Multi Client Setup

## Functionalities
1. Accept multiple client connections.
2. Fork a new process for each client connection.
3. Allow the client to send numbers or strings.
4. Add `5` to a number if a number is received and return the result.
5. Reflect the same text back if a string is received.
6. Disconnect a client when it sends `-1`.

## SETUP
I have pre-loaded the program with my Certificates so one can just run the program without creating a new one.

**If you want to Create Your Own Certificate then procede with the following steps**

## Creating Environment
1. Clone/Download this Repository to your System
2. Create a Directory/Folder and Name it `MULTI_OpenSSL`
3. Copy the Programs `MULTI_SERVER_OPENSSL.c` and `MULTI_CLIENT_OPENSSL.c`
4. In the Same Directory Open Terminal in Admin Mode
5. Admin Mode : `sudo su` and enter your credentials

> Perform the Same Steps above to create a New Certificate or Run using the pre-loaded certificate.

## Compile the Program 
```
gcc -o Mclient MULTI_SERVER_OPENSSL.c -lssl -lcrypto
gcc -o Mserver MULTI_CLIENT_OPENSSL.c -lssl -lcrypto
```

## Run the program in Multiple terminals with Multiple Clients and a single Server
```
./client
./server
```

```
Raise a PR to Contribute 
For any Query Contact : arghacious@gmail.com
```