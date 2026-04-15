import httpx
import time
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, jsonify
import jwt as pyjwt

app = Flask(__name__)

freefire_version = "OB53"

# AES Key and IV for encryption
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def get_jwt_from_uid_password(uid, password):
    """Method 1: Get JWT from UID/Password using Star API"""
    try:
        # Fixed working URL
        url = f"https://star-jwt-gen.vercel.app/api/token?uid={uid}&password={password}"
        response = httpx.get(url, timeout=15.0)
        
        if response.status_code == 200:
            data = response.json()
            jwt_token = data.get('token')
            if jwt_token and jwt_token.startswith('ey'):
                return jwt_token
        return None
    except Exception as e:
        print(f"Star API Error: {e}")
        return None

def get_jwt_from_access_token(access_token):
    """Method 2: Get JWT from Access Token using new API"""
    try:
        # Fixed working URL
        url = f"https://100067-connect-uc-ac-jwt.vercel.app/api/jwt?access_token={access_token}"
        response = httpx.get(url, timeout=15.0)
        
        if response.status_code == 200:
            data = response.json()
            # API se 'jwt' field mein token aayega
            jwt_token = data.get('jwt')
            if jwt_token and jwt_token.startswith('ey'):
                return jwt_token
        return None
    except Exception as e:
        print(f"Access Token API Error: {e}")
        return None

def get_jwt_token(uid=None, password=None, access_token=None, jwt_token=None):
    """Main function to get JWT from multiple sources"""
    
    # Priority 1: Direct JWT token
    if jwt_token:
        return jwt_token
    
    # Priority 2: Access Token se generate
    if access_token:
        return get_jwt_from_access_token(access_token)
    
    # Priority 3: UID/Password se generate
    if uid and password:
        return get_jwt_from_uid_password(uid, password)
    
    return None

def get_region_from_jwt(jwt_token):
    """Extract region from JWT token"""
    try:
        decoded = pyjwt.decode(jwt_token, options={"verify_signature": False})
        lock_region = decoded.get('lock_region', 'IND')
        return lock_region.upper()
    except Exception as e:
        print(f"Region decode error: {e}")
        return 'IND'

def get_region_url(region):
    """Get appropriate server URL based on region"""
    region = region.upper()
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    elif region in ["BR", "US", "SAC", "NA"]:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ggblueshark.com/"

def create_join_payload(clan_id):
    """Create encrypted join request payload"""
    message = bytearray()
    clan_id_int = int(clan_id)
    message.extend(b'\x08')
    while clan_id_int > 127:
        message.append((clan_id_int & 127) | 128)
        clan_id_int >>= 7
    message.append(clan_id_int & 127)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes(message), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def create_leave_payload():
    """Create encrypted leave request payload"""
    message = bytearray()
    message.extend(b'\x08\x02')
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes(message), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

@app.route('/join', methods=['GET'])
def join_clan():
    """Send clan join request"""
    clan_id = request.args.get('clan_id')
    
    # Multiple auth methods
    jwt_token = request.args.get('jwt')
    access_token = request.args.get('access_token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not clan_id:
        return jsonify({"success": False, "error": "clan_id is required"}), 400
    
    # Get JWT from any available source
    final_token = get_jwt_token(
        jwt_token=jwt_token,
        access_token=access_token,
        uid=uid,
        password=password
    )
    
    if not final_token:
        return jsonify({
            "success": False, 
            "error": "Failed to get JWT token. Provide one of: jwt, access_token, or uid+password"
        }), 400
    
    # Get region and server URL
    region = get_region_from_jwt(final_token)
    base_url = get_region_url(region)
    url = f"{base_url}/RequestJoinClan"
    host = base_url.replace("https://", "")
    
    # Create encrypted payload
    encrypted_data = create_join_payload(clan_id)
    
    # Headers
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {final_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": host,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_data)
        
        if response.status_code == 200:
            return jsonify({
                "success": True,
                "message": "✅ Clan join request sent successfully",
                "clan_id": clan_id,
                "region": region,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
        else:
            return jsonify({
                "success": False,
                "message": f"Failed with status {response.status_code}",
                "clan_id": clan_id,
                "region": region,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/quit_clan', methods=['GET'])
def leave_clan():
    """Leave current clan"""
    # Multiple auth methods
    jwt_token = request.args.get('jwt')
    access_token = request.args.get('access_token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    # Get JWT from any available source
    final_token = get_jwt_token(
        jwt_token=jwt_token,
        access_token=access_token,
        uid=uid,
        password=password
    )
    
    if not final_token:
        return jsonify({
            "success": False, 
            "error": "Failed to get JWT token. Provide one of: jwt, access_token, or uid+password"
        }), 400
    
    # Get region and server URL
    region = get_region_from_jwt(final_token)
    base_url = get_region_url(region)
    url = f"{base_url}/RequestLeaveClan"
    host = base_url.replace("https://", "")
    
    # Create encrypted payload
    encrypted_data = create_leave_payload()
    
    # Headers
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {final_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/octet-stream",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": host,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_data)
        
        if 200 <= response.status_code < 300:
            return jsonify({
                "success": True,
                "message": "✅ Successfully left the clan",
                "region": region,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
        else:
            return jsonify({
                "success": False,
                "message": f"Failed with status {response.status_code}",
                "region": region,
                "status_code": response.status_code,
                "timestamp": time.time()
            })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/test', methods=['GET'])
def test_token():
    """Test JWT generation from different sources"""
    jwt_token = request.args.get('jwt')
    access_token = request.args.get('access_token')
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    final_token = get_jwt_token(
        jwt_token=jwt_token,
        access_token=access_token,
        uid=uid,
        password=password
    )
    
    if final_token:
        region = get_region_from_jwt(final_token)
        return jsonify({
            "success": True,
            "message": "✅ Token generated successfully",
            "token_preview": final_token[:50] + "...",
            "token_length": len(final_token),
            "region": region,
            "source": "jwt" if jwt_token else ("access_token" if access_token else "uid_password")
        })
    else:
        return jsonify({
            "success": False, 
            "error": "Failed to generate token",
            "provided": {
                "jwt": bool(jwt_token),
                "access_token": bool(access_token),
                "uid": bool(uid),
                "password": bool(password)
            }
        }), 400

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "name": "FreeFire Clan Manager",
        "version": "3.0",
        "description": "Support multiple authentication methods",
        "auth_methods": {
            "1_direct_jwt": "?jwt=YOUR_JWT_TOKEN",
            "2_access_token": "?access_token=YOUR_ACCESS_TOKEN",
            "3_uid_password": "?uid=XXX&password=XXX"
        },
        "endpoints": {
            "join": "/join?clan_id=XXX&{auth}",
            "leave": "/leave?{auth}",
            "test": "/test?{auth}"
        },
        "examples": {
            "join_with_uid": "/join?clan_id=123456&uid=46788889103&password=S_K9D7R_hhjj47OG8",
            "join_with_access_token": "/join?clan_id=123456&access_token=YOUR_ACCESS_TOKEN",
            "join_with_jwt": "/join?clan_id=123456&jwt=eyJhbGciOiJIUzI1NiIs..."
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "running",
        "version": freefire_version,
        "timestamp": time.time()
    })

if __name__ == '__main__':
    port = 8080
    print("="*60)
    print("🔥 FREEFIRE CLAN MANAGER - MULTI AUTH SUPPORT")
    print("="*60)
    print(f"📍 Port: {port}")
    print(f"🎮 Version: {freefire_version}")
    print("\n📌 AUTHENTICATION METHODS:")
    print("-"*40)
    print("1️⃣  Direct JWT:")
    print("   ?jwt=eyJhbGciOiJIUzI1NiIs...")
    print("\n2️⃣  Access Token:")
    print("   ?access_token=YOUR_ACCESS_TOKEN")
    print("\n3️⃣  UID + Password:")
    print("   ?uid=477899103&password=S_hyuuhyhuhuhuhuhuR_47OG8")
    print("\n📌 ENDPOINTS:")
    print("-"*40)
    print("🔹 JOIN CLAN:")
    print("   /join?clan_id=123456&uid=xxx&password=xxx")
    print("   /join?clan_id=123456&access_token=xxx")
    print("   /join?clan_id=123456&jwt=xxx")
    print("\n🔹 LEAVE CLAN:")
    print("   /leave?uid=xxx&password=xxx")
    print("   /leave?access_token=xxx")
    print("   /leave?jwt=xxx")
    print("\n🔹 TEST TOKEN:")
    print("   /test?uid=xxx&password=xxx")
    print("   /test?access_token=xxx")
    print("   /test?jwt=xxx")
    print("="*60)
    
    app.run(host='0.0.0.0', port=port, debug=False)