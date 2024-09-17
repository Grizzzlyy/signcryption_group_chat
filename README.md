# Desciption
Group chat client-server application on sockets with signcryption scheme, proposed by Mohsen Toorani and Asghar Beheshti [[1]](#1).

# Features
- Schnorr protocol zero-knowledge key-statement proof (ZKKSP) [[2]](#2) for verifying private key possession to server.
- Server can host several groups
- Every messege is signcrypted

# Usage
Install required packages in venv:
```
pip install -r requirements.txt
```

Run options:
```
server.py [-h] host port db_path
client.py [-h] host port username groupname keys_path
```

Example:
``` python
python server.py 127.0.0.1 9001 data/server_db.json
python client.py 127.0.0.1 9001 Alice gr1 data/alice_key.json
python client.py 127.0.0.1 9001 Bob gr1 data/bob_key.json
python client.py 127.0.0.1 9001 Clark gr2 data/clark_key.json
python client.py 127.0.0.1 9001 Daniel gr2 data/daniel_key.json
```
This will create server and two groups, 'gr1': Alice, Bob, 'gr2': Clark, Daniel.

# Files
`src\`\
--`server.py` - server application\
--`server_structs.py` - server routine (database handler, sessions handler)
--`client.py` - client application\
--`signcryption.py` - signcryption scheme (generate keys, signcrypt, unsigncrypt)\
--`constants.py` - signcryption curve, input vector for AES-256, buffer size for server and clients


# Screenshots
Server:\
![image](https://github.com/user-attachments/assets/280c756a-f22f-485d-95a6-77915a6573a7)

Alice:\
![image](https://github.com/user-attachments/assets/e7225f8e-e68b-4f6a-b1aa-c64bc42a970e)

Bob:\
![image](https://github.com/user-attachments/assets/2f3ce60b-d234-49ad-81e1-1b382f2c03ab)



# References
<a id="1">[1]</a>
Mohsen Toorani and Asghar Beheshti (2010).
A Directly Public Verifiable Signcryption Scheme based on Elliptic Curves
http://arxiv.org/abs/1002.3316

<a id="2">[2]</a>
Chatzigiannakis, Ioannis, et al. (2011).
Elliptic curve based zero knowledge proofs and their applicability on resource constrained devices.
2011 IEEE eighth international conference on mobile ad-hoc and sensor systems. IEEE, 2011.
https://arxiv.org/abs/1002.3316
