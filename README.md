This project centers on creating a custom Virtual Private Network (VPN) designed to provide 
secure data transmission over potentially insecure networks by using strong encryption and key 
exchange protocols. The VPN employs Diffie-Hellman Key Exchange for secure key negotiation 
and AES-256 encryption for data protection, ensuring data confidentiality, integrity, and 
authenticity. Built on a client-server model, the server authenticates incoming connections, 
securely negotiates encryption keys, and logs connection details in a lightweight SQLite database 
to enhance traceability. The Diffie-Hellman algorithm allows the client and server to establish a 
shared secret key without exposing it during transmission, significantly strengthening security. 
This shared key is then used in AES-256, a trusted symmetric encryption standard known for its 
high level of security and efficiency. Testing and performance analysis demonstrated that this VPN 
solution offers a stable and secure connection with minimal latency, even under varying network 
conditions. Overall, this custom VPN provides a robust, flexible approach to secure 
communications that can be adapted to specific security requirements or scaled within larger 
network infrastructures.
