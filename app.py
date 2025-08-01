from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import asyncio
import urllib3
from datetime import datetime, timedelta
import os
import threading
from functools import lru_cache
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

app = Flask(__name__)

# Hardcoded API key
VALID_API_KEY = "NG"

# List of accounts for JWT generation
ACCOUNTS =    [
    {
        "uid": "3756208942",
        "password": "0E0AA254CD453DE291FC8B1219997273EBEF669EF4C6FA5009C174073C5B1AD2"
    },
    {
        "uid": "3757378298",
        "password": "D7D6A8497108E08769B431CDEF90C8D02D3FDF2E07318ECBF0A1E1C517DF1140"
    },
    {
        "uid": "3756195839",
        "password": "FB67868004D6C3018705B71B8C74D33BD598E7C69CCEDCCC0DE36532CEC72B21"
    },
    {
        "uid": "3756199402",
        "password": "FF715C1129CAFF680C369BB9EDD67D3BE7915651A796862302F8E1D580BAB06A"
    },
    {
        "uid": "3756591067",
        "password": "413FEA3C738D90B3A21D5B9A8DF56127289047841252097FB82C9FC216B69066"
    },
    {
        "uid": "3756640059",
        "password": "BB8058B3B1603EB92A5E3EF9B83D38F42493561A31B8D07CCA850F47FA50C663"
    },
    {
        "uid": "3756692630",
        "password": "8C7FD3315B83DB19B24CB898931D9EE2DFA36CC90AE8593A6E573DFA2F1E00D1"
    },
    {
        "uid": "3756676529",
        "password": "470101581F73C04CAACB8E75773FF30DAEE14DDCFC82437531645F7BF2F993D7"
    },
    {
        "uid": "3756205226",
        "password": "455A2765971EF1C908553134729533D6C9DEE7C461D466E6DA92BE029A6FD73F"
    },
    {
        "uid": "3756802699",
        "password": "0C517F749085953156F67C89BD25C98D44BA846C5625C23E8134F4B385A81972"
    },
    {
        "uid": "3756807245",
        "password": "74905523C0CC23D568938BCE4F91134D43A8A7D878DCBDA081C9B18AC618D2B1"
    },
    {
        "uid": "3756202336",
        "password": "41E162D2B91E45B29C9EAE6E2FE1ABE531AE1B67349E8A54DE44000ED0D34E09"
    },
    {
        "uid": "3756631280",
        "password": "53B3679E3926F709E4FA88B9083AEE68B30D22997044022805C3359156A83F97"
    },
    {
        "uid": "3756210953",
        "password": "0D634920C4C13581277CFEA1DC252FD0421E02A220A156C770E95E81FFD12E72"
    },
    {
        "uid": "3756213635",
        "password": "AAC3DF9B35045D639A796BE65790DAE29F24D0318B052B5A4C09F5C585BBE661"
    },
    {
        "uid": "3756216270",
        "password": "5CFEBAF8A85C87E3083A17A9E17C22367828238A3FF5271F7053A386FFF77212"
    },
    {
        "uid": "3756218395",
        "password": "A28F2182738A26DA65781E2D4F07339F93C58A640F56893D3ABF3F3949A7693E"
    },
    {
        "uid": "3756221154",
        "password": "3ACD7A743E07F7AC69069C7F9801F8F27B2106E1363685230972677CB8F6B6B5"
    },
    {
        "uid": "3756223299",
        "password": "75EE3B845FC98F2D8C3AC8630A687B379AFE9F0544CF481EB44BFEE44BC2D056"
    },
    {
        "uid": "3756225965",
        "password": "901D938B8565F3D528AAE7DE682E51CC2088D47CD0CE76F0CAE8F9D297F61817"
    },
    {
        "uid": "3756228491",
        "password": "3D72A31CEDED8A8734A93F89BEA0434320700FA76E86592A9DDF7400A21DDD04"
    },
    {
        "uid": "3756230820",
        "password": "87EFF66122B0159D7CF14FBD5EA91BA017A5EF0CF1C5D617D97A468613765059"
    },
    {
        "uid": "3756232827",
        "password": "A9F80195002809732DBF2C79D1D9804B4B5AB64647E004FDF625350CC34C8A32"
    },
    {
        "uid": "3756234976",
        "password": "1D31C8F356F08BE84988AAF9798BF188BE29FDF5E99226AC6A856705814AED64"
    },
    {
        "uid": "3756237903",
        "password": "248E3FC4A1880A2519CE57C51BDADBCBB5C016DB49E49694F5C2A2375F5A5387"
    },
    {
        "uid": "3756240320",
        "password": "0D518DABD3848A433E6D2C69A5B49AA6665997576D9F5695B9240B18EF1B7DBD"
    },
    {
        "uid": "3756242877",
        "password": "F4DF15E3D0E96E520EFDB0CB023E953E5DAEA3C4B06398A6440C53D3D37E2EC3"
    },
    {
        "uid": "3756244984",
        "password": "DBE60589FF557682166C1AC42593870D04A01FAF74076EE2CB121319C06FEBBE"
    },
    {
        "uid": "3756247970",
        "password": "31B817265D7C13FD5EA4D70067C2F3906C7BDADBC8E8F9F9AE1010FD1D0FA3E5"
    },
    {
        "uid": "3756250386",
        "password": "3B5142577281C8FF50617B0729A5ACCFF7970A1D645C45735F2B85AF1B4F645D"
    },
    {
        "uid": "3756252599",
        "password": "8601F922D239F96E106929F979E89900D8CDF582CCBBD3F28147B5C50225892A"
    },
    {
        "uid": "3756593895",
        "password": "4E0C7138CBE73857A6BAD0315DF26B8497B41A26F35262D4756708FEE1E03124"
    },
    {
        "uid": "3756597496",
        "password": "FD720A6B4D3D14DDDA969AA7CD0501C49AE2B75DCC7524658093ADD9E5FA51BC"
    },
    {
        "uid": "3756600552",
        "password": "8AC415D2C0CD7ED8742639CA181523CFD2C79305D411E04A5E06B65360533CE7"
    },
    {
        "uid": "3756603631",
        "password": "8FB7439DFEBDD492EB483F0F3C59F99B2D249D0C177FC3ED2FB87AA77AFEDA38"
    },
    {
        "uid": "3756613281",
        "password": "B6C9AD33B1048B2EE9460A418D8ED7FC555D3B91DBDCACA9311D07044A9F96F4"
    },
    {
        "uid": "3756619650",
        "password": "F7CF28663B91631C96A6A520A454BF9DAAE9251EDCF6AA583162CE2B1862EE0E"
    },
    {
        "uid": "3756623911",
        "password": "9FD3EFA134F5B27008A96CB82FC13DEC15787A7DCC5790AF365053913AD62A5B"
    },
    {
        "uid": "3756627445",
        "password": "0738009FC314D76FD01F2B4473791C9B9F5F84B4F4DBDDCD3765C29423787ECF"
    },
    {
        "uid": "3756636441",
        "password": "1CFA65867C905DEE7306D21CCC5ACEF2098CEBD62F72C9F64102145CE4FBFD5A"
    },
    {
        "uid": "3756643313",
        "password": "67CAEB1C64B669A8B8AD2C4F335A67A91EE07CDD782C7CC4E80A55803CA7CA75"
    },
    {
        "uid": "3756646887",
        "password": "03550F67FDD0D9EF7DD1EF03E202E8A1C2C5409AAF632AB9E74369B656FFC7F9"
    },
    {
        "uid": "3756652266",
        "password": "A3DB3626FDA2EB08BD092DCDFF8843E48BA639FAD7890DA8AD70FBEA269D1F0C"
    },
    {
        "uid": "3756656089",
        "password": "16C02F1B11FE9DB70F0C2532E33BDF00C8F566B9305C8ECAE7384922D8810889"
    },
    {
        "uid": "3756661190",
        "password": "0BF14F448A73119AD6EB47C8DC5500520AE5BF81A6409317751B0C4684296142"
    },
    {
        "uid": "3756667622",
        "password": "A64D13BEB86124CA31F265D0658BDD52ACF8AC635239FC55D406D710933FD5BA"
    },
    {
        "uid": "3756672754",
        "password": "5C190931BE9E2349C81A59838880682724347FC67B2ABF189B46F67046492FA4"
    },
    {
        "uid": "3756682105",
        "password": "BD1951F2F5FD84548BD6EA1CE7306876C01DD0B2C9FDD32D2859E608B6541947"
    },
    {
        "uid": "3756685328",
        "password": "2074B340CC7CF59206A0215E26AC9508CE443914FA3C3EAA72E71A375AEC40B7"
    },
    {
        "uid": "3756688787",
        "password": "4142D2E66687DF0068F0F723668B2576989DE574ED600678C6F76D3AFF3E5D38"
    },
    {
        "uid": "3756700391",
        "password": "1E66FCBD5FD44CCCFCDEAD40025B175293F7B7F25C3DE0B8502FE66FBE392532"
    },
    {
        "uid": "3756705000",
        "password": "DD493CD4C84E2B176E72FD9875AF8B8ABC18E9FDACD35779DECDEE325201F267"
    },
    {
        "uid": "3756709656",
        "password": "7A9CD1CCBB877EE4BFCDBF5B6248BB678FFA9B6BDD95F968CE7D400C9C73ADD4"
    },
    {
        "uid": "3756747051",
        "password": "FCC826D6453A91524733647E136E227743D59EC713517153E54F529724B4D262"
    },
    {
        "uid": "3756789250",
        "password": "49EF784D3B5A7A9442588A8ED7C37254911FD442BEF9F7A89E1CFFF2CF53DD70"
    },
    {
        "uid": "3756793950",
        "password": "48AFCBCF2802068D901F0D012A305E9F684BDF63E79A6ED00A53FEA1C819531A"
    },
    {
        "uid": "3756797991",
        "password": "CDFEF763C8588457A757A0386671FFB4B0ACE791BE52936DAD68C5A08D6F17A5"
    },
    {
        "uid": "3756813487",
        "password": "2E09409BEA95AD734ADF6B7B76C5F6631A4DD306A45D1B7DAFFD8B3CC3D0364D"
    },
    {
        "uid": "3756818496",
        "password": "8E67711C9696B4A0B1387B3390CF540380F0E0BD4D5470342C386E4D4333C580"
    },
    {
        "uid": "3756823334",
        "password": "5209BAC6CEBE024265CA3C67A7CD93ADA9BC58BEE5583F2F561EDAD37E037F87"
    },
    {
        "uid": "3756828487",
        "password": "AE9A922BEE85836AF8545928AF547A3A67B30E3C7FAF83FCFA93488263DA7FC8"
    },
    {
        "uid": "3756832997",
        "password": "FC65050AB072CE14B609AD0DF89331F8CE432E6904015A6B2F59EC0717BAE0B8"
    },
    {
        "uid": "3756837630",
        "password": "3FD6D8068EDFB167C27A9C34D664B6B012651CD00E57A38FBCEC097C53573BF1"
    },
    {
        "uid": "3756845139",
        "password": "FB74C0FAAF10246A77B499EF9EE3BABBE7BDCE91DD4DCCD4451936DF1D1208CE"
    },
    {
        "uid": "3756848655",
        "password": "DE29868993193AB25E2867B0A1697E3193FA7CB0B5DB5B9FC092A4345A8D800D"
    },
    {
        "uid": "3756851967",
        "password": "DCCAD9AE4D885E926AC3A8502106885FC52780D429B52C962E3E1E0B9B1EB7A1"
    },
    {
        "uid": "3756855800",
        "password": "C6E4A9304285525E580D34AA5C27DFABA707DBBBE25D293EFB08C067FC3788E4"
    },
    {
        "uid": "3756858910",
        "password": "08B0CC15C9412B1BA7333AC05B4317F8F9CEF80DD4E1087041FFF110B53FA051"
    },
    {
        "uid": "3756862208",
        "password": "53C1AAC4F8606E5445739469F40DBEF6D43DFC2DDF51B512B3E85F30E6C5884B"
    },
    {
        "uid": "3756865979",
        "password": "5F8763B0A53D7251A22DDA3B75BCE8C6888D00E637CB39D2CC8B4A143C14D7C8"
    },
    {
        "uid": "3756869026",
        "password": "0A971397561B3FDE3961F9187F45AF3C7853563C3026209E712FB72BF8EE715C"
    },
    {
        "uid": "3756872660",
        "password": "3502FB8004C45D493410FE582CDF0A9505A23F9CFB6F6F5FEE539C3EB1EF8A18"
    },
    {
        "uid": "3756875697",
        "password": "B453FCCB7876A109863F3019D317F67CF77CB9DDEB5312A07C82A4B72C9C5767"
    },
    {
        "uid": "3756878948",
        "password": "C7C50F107961B25B80B5AD09D3AF5C662E454FA0A7D1ADFD0A0E2FCEC96E7E1D"
    },
    {
        "uid": "3756882040",
        "password": "6FF601652F33D5BC1A2709CD1A51F7F0415BBC00002952FB32BF8297AB00DF33"
    },
    {
        "uid": "3756884863",
        "password": "64CE592E3CFCF9813C7B14308F5C3E4B113AEA2B76011DC34A3A9E523047FC7F"
    },
    {
        "uid": "3756890057",
        "password": "3BC20FACDD86404262AAF9DDA8A4E4AE6F2A6163F98CFAE5FAA098BB813441A0"
    },
    {
        "uid": "3756893948",
        "password": "9F8AEFA0A0BB5EBD8AC09E2768FA6D84BB65C53DD7C679E99490ED5D3543CE3B"
    },
    {
        "uid": "3756896660",
        "password": "18F9AEF4021F19D2B87E88F16158BC06AF93737485237DD59E7418A639A1516F"
    },
    {
        "uid": "3756900699",
        "password": "75283D957221050BA30193390721E76ACA41D612A04F6DC6C88A47482518F1DA"
    },
    {
        "uid": "3756904104",
        "password": "E633E7A899C05B932DAA5E716DAD0C65A3A2813ABE5392E92C013DC9AD3471A9"
    },
    {
        "uid": "3756908662",
        "password": "5946733E4946BC862E7B0699839BC6E5736217757F6E87EE82A8186A6717480D"
    },
    {
        "uid": "3756911860",
        "password": "5F837ADCF5BC8146D9D393F34FCAA0EBCB0D14A3C9D5FA8F201DA686D9987AE5"
    },
    {
        "uid": "3756915260",
        "password": "20781608EE2A718B4C7D9FBFEA0D7B6898D7A214AB9F22F8F0DCACA596C95051"
    },
    {
        "uid": "3756918865",
        "password": "D00D2954099E0D46F77426EF4B6A24A66FBDA58B96D6567B4E742CE596AFBE83"
    },
    {
        "uid": "3756922008",
        "password": "7A75275731FC9D0BCA290B113EF7182F6D803D8EFFC4A72A7B857B1326383ABE"
    },
    {
        "uid": "3757319790",
        "password": "F1D5FB48ECC4C14B3E991A9AE821188FA3F66813815FBB3C9F4B75F033059C79"
    },
    {
        "uid": "3757323955",
        "password": "EE2ECDBD9083A036A197C8B71BAC183F7E9EDE7ED1322B295DC38A05DF9A74CF"
    },
    {
        "uid": "3757327725",
        "password": "98CE22319E5D6C2CEDF7BBAE5D755467594D4BF33A6BAB69FFA172BDCD1018D9"
    },
    {
        "uid": "3757331811",
        "password": "D1A6B5E700E9E72072C5BC522983F35B69C97F9E20AF29CEDA7B6E7584B85483"
    },
    {
        "uid": "3757335585",
        "password": "BEB50EEAF8A0F8CE6BC0F0A8796FBD3A4917B516FCE27C2C3127E2ABF083B6D0"
    },
    {
        "uid": "3757340023",
        "password": "C7A53E91006EDA75EEF175157F59CD3555D4E3F2002D9E42862C70F881F4AD94"
    },
    {
        "uid": "3757344506",
        "password": "558217A8DF791778F3C345201A74293F63ACB3A50A0BE3A5CC2F7C77098B1DFF"
    },
    {
        "uid": "3757348721",
        "password": "F22657DAB03ABE14A440157A32FC517C74B400333328BCA1A1737E1C7C4C11C6"
    },
    {
        "uid": "3757351624",
        "password": "B4CF69ECBB60AFB3F9E91AD7EAA4146BAD729D5E99386A9A86A7A14B31D8191A"
    },
    {
        "uid": "3757354411",
        "password": "B1863A93A68C54956B04D7B9F1127A7787F0E8935D041926FCEB7ED459FCC4E0"
    },
    {
        "uid": "3757358105",
        "password": "DA671843EF75D13AF1D5E2C2A80166A10EBCC0A9414AC689BE6C1E84C513232F"
    },
    {
        "uid": "3757362777",
        "password": "9F9BC9A3FD737BDB83CB2ABD75D153C7DCA9A44573A4B4C068606063CA01B6A4"
    },
    {
        "uid": "3757367156",
        "password": "A27933C8125452335B4A3542C23C4EB199AC20DEB6291788D25C135C2F7C6320"
    },
    {
        "uid": "3757371457",
        "password": "525D6E47581DDA7FE4A3CA1D440766215A5F4DA84CD9DE43E391924B31B21289"
    },
    {
        "uid": "3757375006",
        "password": "BFBE62B0CAAA361EB6A8FC5680718F17885066A2949C09E235A36ED335A716BF"
    }
]

# JWT API endpoints
JWT_ENDPOINTS = [
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token",
    "https://jnl-gen-jwt.vercel.app/token"
]

# Cache for tokens
token_cache = {}
last_token_update = {}

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

async def get_jwt_token(account, region):
    try:
        # Check if we have a recent token for this account and region
        cache_key = f"{account['uid']}_{region}"
        if cache_key in token_cache:
            last_update = last_token_update.get(cache_key, 0)
            if time.time() - last_update < 3600 * 7:  # 7 hours (refresh before 8 hours)
                return token_cache[cache_key]
        
        # Rotate through JWT endpoints
        endpoint_idx = hash(account['uid']) % len(JWT_ENDPOINTS)
        endpoint = JWT_ENDPOINTS[endpoint_idx]
        
        url = f"{endpoint}?uid={account['uid']}&password={account['password']}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'live' and data.get('region') == region:
                        token = data['token']
                        token_cache[cache_key] = token
                        last_token_update[cache_key] = time.time()
                        return token
        return None
    except Exception as e:
        return None

async def load_tokens(region):
    tokens = []
    for account in ACCOUNTS:
        token = await get_jwt_token(account, region)
        if token:
            tokens.append({"token": token})
    return tokens

async def make_request(encrypt, region, token, session):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as response:
            if response.status != 200:
                return None
            binary = await response.read()
            return decode_protobuf(binary)
    except Exception as e:
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        return None

@app.route('/visit', methods=['GET'])
async def visit():
    api_key = request.args.get('api_key')
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    
    if not all([api_key, target_uid, region]):
        return jsonify({"error": "API key, UID, and region are required"}), 400
        
    if api_key != VALID_API_KEY:
        return jsonify({"error": "Invalid API key"}), 401
        
    try:
        tokens = await load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens.")
            
        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption of target UID failed.")
            
        total_visits = len(tokens) * 40  # 40 times each call for faster processing
        success_count = 0
        failed_count = 0
        player_name = None
        total_responses = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for token in tokens:
                for _ in range(40):  # 40 API calls per token
                    tasks.append(make_request(encrypted_target_uid, region, token['token'], session))
            
            results = await asyncio.gather(*tasks)
            
            for info in results:
                total_responses.append(info)
                if info:
                    if not player_name:
                        jsone = MessageToJson(info)
                        data_info = json.loads(jsone)
                        player_name = data_info.get('AccountInfo', {}).get('PlayerNickname', '')
                    success_count += 1
                else:
                    failed_count += 1
                
        summary = {
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
            "TotalResponses": len(total_responses)
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
