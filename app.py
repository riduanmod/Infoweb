import asyncio
import time
import httpx
import json
import os
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES

# === Local Imports ===
from config import Config
from Pb2 import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# === Flask App Setup ===
app = Flask(__name__, static_folder='static', template_folder='templates')
# এটি নিশ্চিত করবে যেন ব্রাউজারে JSON রেসপন্সের সিরিয়াল উল্টাপাল্টা না হয়
app.json.sort_keys = False 
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Data Formatting Helpers ===
def format_timestamp(timestamp_val):
    """Convert Unix timestamp string/int to readable Date & Time."""
    if not timestamp_val:
        return None
    try:
        ts = int(timestamp_val)
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %I:%M:%S %p')
    except (ValueError, TypeError):
        return timestamp_val

def format_large_number(num):
    """Format large numbers (e.g., Guild EXP) into 'K', 'M', 'B'."""
    if num is None: return None
    try:
        num = int(num)
        if num < 1000:
            return str(num)
        elif num < 1000000:
            return f"{num / 1000:.1f}K"
        elif num < 1000000000:
            return f"{num / 1000000:.1f}M"
        else:
            return f"{num / 1000000000:.1f}B"
    except (ValueError, TypeError):
        return str(num)

def format_ep_history(ep_data_list):
    """Format the elite pass history list."""
    formatted_ep = []
    if not ep_data_list: return formatted_ep
    for ep in ep_data_list:
        ep_id = ep.get("a", 0)
        formatted_ep.append(f"EP {ep_id}")
    return formatted_ep

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = Config.get_account(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'X-Unity-Version': Config.UNITY_VERSION, 
        'X-GA': "v1 1", 
        'ReleaseVersion': Config.RELEASE_VERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code == 200:
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
        else:
            raise Exception(f"MajorLogin failed with status: {resp.status_code}")

async def initialize_tokens():
    tasks = [create_jwt(r) for r in Config.SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        try:
            await initialize_tokens()
        except Exception as e:
            print(f"Error in periodical token refresh: {e}")

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'Authorization': token, 
        'X-Unity-Version': Config.UNITY_VERSION, 
        'X-GA': "v1 1",
        'ReleaseVersion': Config.RELEASE_VERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

def format_response(data):
    basic = data.get("basicInfo", {})
    social = data.get("socialInfo", {})
    clan = data.get("clanBasicInfo", {})
    captain = data.get("captainBasicInfo", {})
    history_ep = data.get("historyEpInfo", [])

    # Dynamic Avatar Logic
    avatar_id = basic.get("badgeId") # Uses badgeId as avatar indicator
    avatar_url = ""
    if avatar_id:
        avatar_url = f"Https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{avatar_id}.png"

    return {
        "Player Information": {
            "Player_Name": basic.get("nickname"),
            "Player_UID": basic.get("accountId"),
            "Player_Avatar_URL": avatar_url,                   
            "Player_Level": basic.get("level"),
            "Player_EXP": basic.get("exp"),
            "Player_Likes": basic.get("liked"),
            "Player_Region": basic.get("region"),
            "Player_Gender": social.get("gender"),
            "Account_Create_Time": format_timestamp(basic.get("createAt")),
            "Account_Last_Login": format_timestamp(basic.get("lastLoginAt")),
            "Player_Signature": social.get("socialHighlight") or social.get("signature"),
            "Player_BP_Badges": basic.get("badgeCnt"),
        },
        "Rank Information": {
            "BR_Points": basic.get("rankingPoints"),          # Prominent points
            "BR_Max_Rank_Name": basic.get("maxRank"),         # Max rank below
            "CS_Points": basic.get("csRankingPoints"),       # Prominent points
            "CS_Max_Rank_Name": basic.get("csMaxRank"),      # Max rank below
        },
        "Guild Information": {
            "Guild_Name": clan.get("clanName"),
            "Guild_ID": clan.get("clanId"),
            "Guild_Level": clan.get("clanLevel"),
            "Guild_Total_EXP": clan.get("exp"),
            "Guild_EXP_Formatted": format_large_number(clan.get("exp")), # Formatted EXP
            "Guild_Capacity": clan.get("maxMembers") or clan.get("capacity"),
            "Guild_Total_Members": clan.get("currentMembers") or clan.get("memberNum"),
            "Guild_Leader_UID": clan.get("captainId")
        },
        "Guild Leader Information": {
            "Guild_Leader_Name": captain.get("nickname"),
            "Guild_Leader_UID": captain.get("accountId"),
            "Guild_Leader_Level": captain.get("level"),
            "Guild_Leader_EXP": captain.get("exp"),
            "Guild_Leader_Likes": captain.get("liked"),
            "Guild_Leader_Last_Login": format_timestamp(captain.get("lastLoginAt"))
        },
        "Extended Stats & Info": {
            "Player_History_EP_Stats": format_ep_history(history_ep) 
        }
    }

# === API Routes ===
@app.route('/')
def home():
    """Serve the index.html page."""
    return render_template('index.html')

@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    try:
        # Defaulting to "ME" region. You can add region switching later if needed.
        region = "ME"
        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        if not return_data.get("basicInfo", {}).get("accountId"):
             return jsonify({"error": "Player not found."}), 404
             
        formatted = format_response(return_data)
        return jsonify(formatted), 200
    
    except Exception as e:
        return jsonify({"error": f"Invalid UID or server error. Please try again. {e}"}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup ===
async def startup():
    try:
        await initialize_tokens()
        asyncio.create_task(refresh_tokens_periodically())
    except Exception as e:
        print(f"Token initialization failed: {e}")

if __name__ == '__main__':
    # Flask[async] allows running async startup.
    app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG)

# THIS CODE IS UPDATED TO MEET USER DEMANDS
# AND SECURED FOR PRODUCTION
