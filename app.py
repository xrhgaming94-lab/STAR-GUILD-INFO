import httpx
import time
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, redirect, url_for
from datetime import datetime
import asyncio

# ===================== CONFIG =====================
app = Flask(__name__)
freefire_version = "OB53"
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
jwt_tokens = {}  # Store tokens by region
# =================================================

# ===================== REGION CONFIG =====================
def get_region_credentials(region):
    r = region.upper()
    if r == "IND":
        return "uid=4447838607&password=BRRAJA_1ZIVK_RIZER_8253D"
    elif r == "BD":
        return "uid=4218400521&password=BY_XRSUPER-JZRQ3RURQ-XRRRR"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4218400521&password=BY_XRSUPER-JZRQ3RURQ-XRRRR"
    else:
        return "uid=4218400521&password=BY_XRSUPER-JZRQ3RURQ-XRRRR"

# ===================== PROTOBUF PARSING =====================
def parse_varint(data, offset):
    """Parse protobuf varint"""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            return None, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset

def parse_protobuf_response(data):
    """Manually parse protobuf response to get all fields"""
    result = {}
    offset = 0
    data_len = len(data)
    
    while offset < data_len:
        if offset >= data_len:
            break
            
        # Read field tag
        tag, offset = parse_varint(data, offset)
        if tag is None:
            break
            
        field_number = tag >> 3
        wire_type = tag & 0x07
        
        if wire_type == 0:  # Varint
            value, offset = parse_varint(data, offset)
            if value is not None:
                result[field_number] = value
                
        elif wire_type == 2:  # Length-delimited (string, bytes, nested message)
            length, offset = parse_varint(data, offset)
            if length is None or offset + length > data_len:
                break
                
            value = data[offset:offset + length]
            offset += length
            
            # Try to parse as nested message if it looks like one
            if len(value) > 0 and value[0] & 0x80:
                nested = parse_protobuf_response(value)
                if nested:
                    result[field_number] = nested
                else:
                    try:
                        result[field_number] = value.decode('utf-8', errors='ignore')
                    except:
                        result[field_number] = value.hex()
            else:
                try:
                    result[field_number] = value.decode('utf-8', errors='ignore')
                except:
                    result[field_number] = value.hex()
                    
        elif wire_type == 1:  # 64-bit (fixed64)
            if offset + 8 <= data_len:
                value = struct.unpack('<Q', data[offset:offset+8])[0]
                result[field_number] = value
                offset += 8
            else:
                break
        elif wire_type == 5:  # 32-bit (fixed32)
            if offset + 4 <= data_len:
                value = struct.unpack('<I', data[offset:offset+4])[0]
                result[field_number] = value
                offset += 4
            else:
                break
        else:
            break
    
    return result

# ===================== JWT TOKEN =====================
async def get_jwt_token(region):
    global jwt_tokens
    credentials = get_region_credentials(region)
    
    # Parse credentials to get uid and password
    parts = credentials.split('&')
    uid = None
    password = None
    for part in parts:
        if part.startswith('uid='):
            uid = part.split('=')[1]
        elif part.startswith('password='):
            password = part.split('=')[1]
    
    if not uid or not password:
        print(f"[-] Invalid credentials format for {region}")
        return False
    
    # Use the working JWT endpoint
    url = f"https://star-jwt-gen.vercel.app/token?uid={uid}&password={password}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # The token is in "Token" field
                if data.get('token'):
                    jwt_tokens[region.upper()] = data['token']
                    print(f"[+] JWT Token Updated for {region}")
                    return True
                else:
                    print(f"[-] No Token field in response for {region}: {data}")
                    return False
            else:
                print(f"[-] HTTP {response.status_code} for {region}")
                return False
    except Exception as e:
        print(f"[-] JWT Token Error for {region}: {e}")
        return False

async def token_updater():
    regions = ["IND", "BD", "BR", "US", "SAC", "NA"]
    while True:
        for region in regions:
            await get_jwt_token(region)
            await asyncio.sleep(10)
        await asyncio.sleep(8 * 3600)

# ===================== CORE CLAN INFO FUNCTION =====================
def fetch_clan_info(clan_id, region, jwt_token=None):
    """Core function to fetch clan info with either stored or provided token"""
    try:
        # Use provided token or stored token
        if jwt_token:
            token_to_use = jwt_token
        else:
            if region not in jwt_tokens or not jwt_tokens[region]:
                return None, f"JWT token for region {region} not ready"
            token_to_use = jwt_tokens[region]

        # Create request protobuf
        request_data = bytearray()
        
        # Encode field 1 (clan_id)
        clan_id_int = int(clan_id)
        tag1 = (1 << 3) | 0
        while tag1 > 0:
            byte = tag1 & 0x7F
            tag1 >>= 7
            if tag1 > 0:
                byte |= 0x80
            request_data.append(byte)
        
        # Encode clan_id value
        value = clan_id_int
        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value > 0:
                byte |= 0x80
            request_data.append(byte)
        if clan_id_int == 0:
            request_data.append(0)
        
        # Encode field 2 (value 1)
        tag2 = (2 << 3) | 0
        while tag2 > 0:
            byte = tag2 & 0x7F
            tag2 >>= 7
            if tag2 > 0:
                byte |= 0x80
            request_data.append(byte)
        request_data.append(1)
        
        # Encrypt request
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_request = cipher.encrypt(pad(bytes(request_data), 16))
        
        # Determine API endpoint based on region
        region_upper = region.upper()
        if region_upper == "IND":
            url = "https://client.ind.freefiremobile.com/GetClanInfoByClanID"
            host = "client.ind.freefiremobile.com"
        elif region_upper == "BD":
            url = "https://clientbp.ggblueshark.com/GetClanInfoByClanID"
            host = "clientbp.ggblueshark.com"
        elif region_upper in ["BR", "SAC"]:
            url = "https://client.br.freefiremobile.com/GetClanInfoByClanID"
            host = "client.br.freefiremobile.com"
        elif region_upper in ["US", "NA"]:
            url = "https://client.na.freefiremobile.com/GetClanInfoByClanID"
            host = "client.na.freefiremobile.com"
        else:
            url = "https://client.ind.freefiremobile.com/GetClanInfoByClanID"
            host = "client.ind.freefiremobile.com"

        # Request headers
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token_to_use}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": freefire_version,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Host": host,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        # Synchronous HTTP using httpx
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_request)

        if response.status_code != 200:
            return None, f"HTTP {response.status_code}: {response.text[:200]}"

        # Parse response
        parsed_data = parse_protobuf_response(response.content)
        
        # Map field numbers to readable names based on your findings
        clan_info = {
            "status": "success",
            "requested_region": region_upper,
            "guild_id": parsed_data.get(1, 0),
            "clan_name": parsed_data.get(2, ""),
            "level": parsed_data.get(5, 0),
            "xp": parsed_data.get(4, 0),
            "score": parsed_data.get(36, 0),  # Glory points
            "rank": parsed_data.get(39, 0),  # Guild position in region
            "region": parsed_data.get(13, ""),
            "welcome_message": parsed_data.get(12, ""),
            "created_at": parsed_data.get(40, 0),
            "updated_at": parsed_data.get(9, 0),
            "last_active": parsed_data.get(44, 0),
            "clan_id": parsed_data.get(1, 0),
            "total_members": parsed_data.get(6, 0),
            "members_online": parsed_data.get(7, 0),
            "error_code": parsed_data.get(41, 0),
            "owner_id": parsed_data.get(4, 0),
            "acting_leader_id": parsed_data.get(23, 0),
            "managers_count": parsed_data.get(38, 0),
            "activity_points": parsed_data.get(37, 0),
            "guild_message": parsed_data.get(12, ""),
            "tags": parsed_data.get(14, ""),
            "members_list": parsed_data.get(15, []),
            "raw_response": parsed_data  # Keep raw for debugging
        }
        
        # Convert timestamps
        def format_timestamp(ts):
            if ts and ts > 0:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            return None
        
        clan_info["created_at"] = format_timestamp(clan_info["created_at"])
        clan_info["updated_at"] = format_timestamp(clan_info["updated_at"])
        clan_info["last_active"] = format_timestamp(clan_info["last_active"])
        
        return clan_info, None

    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, str(e)

# ===================== ENDPOINTS =====================

@app.route('/', methods=['GET'])
def home():
    """Show all available endpoints"""
    endpoints = {
        "available_endpoints": {
            "/": {
                "method": "GET",
                "description": "Show all available endpoints"
            },
            "/info": {
                "method": "GET",
                "description": "Get clan info using stored JWT token",
                "parameters": {
                    "clan_id": "required - Clan/Guild ID",
                    "region": "optional - IND, BD, BR, US, SAC, NA (default: IND)"
                },
                "example": "/info?clan_id=3086500970&region=BD"
            },
            "/info/direct": {
                "method": "GET",
                "description": "Get clan info using your own JWT token",
                "parameters": {
                    "clan_id": "required - Clan/Guild ID",
                    "region": "required - IND, BD, BR, US, SAC, NA",
                    "jwt_token": "required - Your JWT token"
                },
                "example": "/info/direct?clan_id=3086500970&region=BD&jwt_token=YOUR_TOKEN"
            },
            "/refresh": {
                "method": "GET",
                "description": "Refresh all JWT tokens manually",
                "example": "/refresh"
            },
            "/health": {
                "method": "GET",
                "description": "Check API health status",
                "example": "/health"
            },
            "/info/debug": {
                "method": "GET",
                "description": "Debug endpoint to see raw response",
                "parameters": {
                    "clan_id": "required - Clan/Guild ID",
                    "region": "required - Region",
                    "jwt_token": "optional - Your JWT token"
                },
                "example": "/info/debug?clan_id=3086500970&region=BD"
            }
        },
        "regions_supported": ["IND", "BD", "BR", "US", "SAC", "NA"],
        "version": freefire_version,
        "status": "running"
    }
    return jsonify(endpoints)

@app.route('/info', methods=['GET'])
def get_clan_info():
    clan_id = request.args.get('clan_id')
    region = request.args.get('region', 'IND').upper()
    
    if not clan_id:
        return jsonify({"error": "clan_id is required"}), 400

    if region not in jwt_tokens or not jwt_tokens[region]:
        return jsonify({"error": f"JWT token for region {region} not ready. Try /refresh to update tokens."}), 503

    result, error = fetch_clan_info(clan_id, region)
    
    if error:
        return jsonify({"error": error}), 500
    
    return jsonify(result)

@app.route('/info/direct', methods=['GET'])
def get_clan_info_direct():
    clan_id = request.args.get('clan_id')
    region = request.args.get('region', 'IND').upper()
    jwt_token = request.args.get('jwt_token')
    
    if not clan_id:
        return jsonify({"error": "clan_id is required"}), 400
    
    if not jwt_token:
        return jsonify({"error": "jwt_token is required for this endpoint"}), 400
    
    if not clan_id.isdigit():
        return jsonify({"error": "clan_id must be a number"}), 400
    
    valid_regions = ["IND", "BD", "BR", "US", "SAC", "NA"]
    if region not in valid_regions:
        return jsonify({"error": f"Invalid region. Valid regions: {', '.join(valid_regions)}"}), 400
    
    result, error = fetch_clan_info(clan_id, region, jwt_token)
    
    if error:
        return jsonify({"error": error}), 500
    
    result["token_source"] = "direct_provided"
    return jsonify(result)

@app.route('/refresh', methods=['GET'])
def refresh_tokens():
    """Manually refresh all JWT tokens"""
    global jwt_tokens
    
    async def refresh_all():
        regions = ["IND", "BD", "BR", "US", "SAC", "NA"]
        results = {}
        for region in regions:
            success = await get_jwt_token(region)
            results[region] = "success" if success else "failed"
            await asyncio.sleep(1)
        return results
    
    try:
        # Run async refresh
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(refresh_all())
        loop.close()
        
        return jsonify({
            "status": "completed",
            "results": results,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Refresh failed: {str(e)}"}), 500

@app.route('/info/debug', methods=['GET'])
def get_clan_info_debug():
    """Debug endpoint that shows raw response"""
    clan_id = request.args.get('clan_id')
    region = request.args.get('region', 'IND').upper()
    jwt_token = request.args.get('jwt_token')
    
    if not clan_id:
        return jsonify({"error": "clan_id is required"}), 400
    
    if not jwt_token:
        if region not in jwt_tokens or not jwt_tokens[region]:
            return jsonify({"error": f"JWT token for region {region} not ready"}), 503
        jwt_token = jwt_tokens[region]
    
    try:
        # Create and encrypt request
        request_data = bytearray()
        clan_id_int = int(clan_id)
        tag1 = (1 << 3) | 0
        while tag1 > 0:
            byte = tag1 & 0x7F
            tag1 >>= 7
            if tag1 > 0:
                byte |= 0x80
            request_data.append(byte)
        
        value = clan_id_int
        while value > 0:
            byte = value & 0x7F
            value >>= 7
            if value > 0:
                byte |= 0x80
            request_data.append(byte)
        if clan_id_int == 0:
            request_data.append(0)
        
        tag2 = (2 << 3) | 0
        while tag2 > 0:
            byte = tag2 & 0x7F
            tag2 >>= 7
            if tag2 > 0:
                byte |= 0x80
            request_data.append(byte)
        request_data.append(1)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_request = cipher.encrypt(pad(bytes(request_data), 16))
        
        # Make request
        region_upper = region.upper()
        if region_upper == "IND":
            url = "https://client.ind.freefiremobile.com/GetClanInfoByClanID"
        elif region_upper == "BD":
            url = "https://clientbp.ggblueshark.com/GetClanInfoByClanID"
        elif region_upper in ["BR", "SAC"]:
            url = "https://client.br.freefiremobile.com/GetClanInfoByClanID"
        else:
            url = "https://client.na.freefiremobile.com/GetClanInfoByClanID"
        
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/octet-stream",
            "ReleaseVersion": freefire_version,
        }
        
        with httpx.Client(timeout=30.0) as client:
            response = client.post(url, headers=headers, content=encrypted_request)
        
        return jsonify({
            "status_code": response.status_code,
            "response_hex": response.content.hex()[:500],
            "response_length": len(response.content),
            "parsed": parse_protobuf_response(response.content)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    regions_status = {}
    for region in ["IND", "BD", "BR", "US", "SAC", "NA"]:
        regions_status[region] = "ready" if region in jwt_tokens and jwt_tokens[region] else "not ready"
    
    return jsonify({
        "status": "running",
        "regions": regions_status,
        "timestamp": datetime.now().isoformat()
    })

# ===================== STARTUP =====================
async def startup():
    print("[🔧] Initializing JWT tokens...")
    regions = ["IND", "BD", "BR", "US", "SAC", "NA"]
    for region in regions:
        await get_jwt_token(region)
        await asyncio.sleep(1)
    print("[✅] Initial token fetch complete")

def start_background_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(token_updater())
    loop.run_forever()

if __name__ == '__main__':
    import sys
    import threading
    import struct
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"[🚀] Starting API on port {port} ...")
    print(f"[📝] Available endpoints: http://localhost:{port}/")
    
    # Start background token updater thread
    bg_thread = threading.Thread(target=start_background_loop, daemon=True)
    bg_thread.start()
    
    # Initial token fetch
    try:
        asyncio.run(startup())
    except Exception as e:
        print(f"[⚠️] Startup warning: {e}")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
