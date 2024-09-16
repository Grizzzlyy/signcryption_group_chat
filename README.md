# Desciption
Group chat client-server application on sockets with signcryption scheme, proposed by Mohsen Toorani and Asghar Beheshti [[1]](#1).

# Features
- Schnorr protocol zero-knowledge key-statement proof (ZKKSP) [[2]](#2) for verifying private key possession to server.
- Server can host several groups
- Every messege is signcrypted
- Malicious client, that sends message, using fake private key. All users in group get warning that there is corrupted message from user \<username\>.

# Usage
Install required packages in venv:
```
pip install -r requirements.txt
```

Run options:
```
server.py [-h] host port
client.py [-h] host port username groupname
```

Example:
``` python
python server.py 127.0.0.1 9001
python client.py 127.0.0.1 9001 Alice gr1
python client.py 127.0.0.1 9001 Bob gr1
python malicious_client.py 127.0.0.1 9001 Attacker gr1
python client.py 127.0.0.1 9001 Clark gr2
python client.py 127.0.0.1 9001 Daniel gr2
```
This will create server and two groups, 'gr1': Alice, Bob, Attacker, 'gr2': Clark, Daniel. When malicious client tries to send message, every member of group will recieve warnings.

# Files
`server.py` - server application\
`client.py` - client application\
`malicious_client.py` - malicious client used for warning demo, using fake private key\
`signcryption.py` - signcryption scheme (generate keys, signcrypt, unsigncrypt)\
`constants.py` - signcryption curve, input vector for AES-256, buffer size for server and clients


# Screenshots
Server:\
![image](https://github.com/user-attachments/assets/e01fc054-2281-4240-b899-9594b11e9331)

Alice:\
![image](https://github.com/user-attachments/assets/c5474460-8afe-4097-be39-22c2867d9416)

Bob:\
![image](https://github.com/user-attachments/assets/1f36b777-b579-4254-917f-3f85a2469104)




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
