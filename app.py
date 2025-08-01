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
ACCOUNTS =    [  {
        "uid": "3922796160",
        "password": "D2BC77E595705F679BBB1C8C86CE79355526BB11AB33146375D7D8686DA1C560"
    },
    {
        "uid": "3922805250",
        "password": "4F55C2E31617D89815E15471F616E08B5227B3212DAC737C497A3A6F938A352B"
    },
    {
        "uid": "3925951710",
        "password": "69AC9DFDA53864CBF7F9CBC8445FA6EB6D946C5EAAFDA7ABB8284BF59235913C"
    },
    {
        "uid": "3925958911",
        "password": "A2BAF81C429A411881598BB15D089E414578647294E1F975435D503463CBE42D"
    },
    {
        "uid": "3925964655",
        "password": "4972D79FEAC3492A6CDCCCAB704A67A777D16E2C39188806FF6ACB53E201875D"
    },
    {
        "uid": "3925970228",
        "password": "CECE2D32EBBB150F2B38A5133D229B22016F8EA5D489248037A305CEBCB182AE"
    },
    {
        "uid": "3925976654",
        "password": "32294E57CFC3F29F36B70572E2477F408C3AB6A7FFE7467E2B4FEB8004E7096C"
    },
    {
        "uid": "3925983337",
        "password": "CCB973C94937CEB133DB54F8DFD9080F64B02355C8FD7CA97FFED1FC54E37F40"
    },
    {
        "uid": "3925989088",
        "password": "1FE99F742D526FE62DB60DDBDD0A2007639C7EA18ACEA92071CA2F3170620F49"
    },
    {
        "uid": "3925993640",
        "password": "D0E1120FDF86F6D336B9554C6960A65A6398DA4AEC6F636BC17C861B0086E74F"
    },
    {
        "uid": "3926037237",
        "password": "ADC12F365C643ACD559DDEBE9CAD2F344E9CA08CB0A09B3BBBA77BF44F865CED"
    },
    {
        "uid": "3926048592",
        "password": "834D8182F32ADC3D2C12FC05D85788EE4D418EA737CD1ABD7C78F84C4221C879"
    },
    {
        "uid": "3926057536",
        "password": "28E272CBD9023D40592AF0421ED71FC135A24CE74C19AB08F29A6ADC7B861C8C"
    },
    {
        "uid": "3926063820",
        "password": "A0326A533CA0E473819B69114D9B1060035FEEB2373DA9F4459624E88267C52D"
    },
    {
        "uid": "3926070834",
        "password": "0F081F34CA7DD16FB9A02D4A6FE88BF0ABC64D7DCE3BC272A500FAA528B8E908"
    },
    {
        "uid": "3926078378",
        "password": "3EB9859526032C5C5D2B98248B361B255724943D2C92E4EE68DD4F3040E537F3"
    },
    {
        "uid": "3926087259",
        "password": "3A0DB90DF34F097DCE415F618F1F7CB2A81C72D4C696EE0BC1FEA0DCE683B856"
    },
    {
        "uid": "3926094900",
        "password": "76485D9E6FCE274A6678DD5702AD6B215779504B21F479BD28D54AD9F3227D37"
    },
    {
        "uid": "3926100801",
        "password": "92C63BBF8CEF904F904CBE426D653A6250B9F6C06C1F40E643E5BE94E82E95CD"
    },
    {
        "uid": "3926107030",
        "password": "F13F80619F3ECB3DE22D673660BF4027F09A9755588E1D45EE3DC20FA33AFE8B"
    },
    {
        "uid": "3929085476",
        "password": "1DFAD26EDD91C87C42BAC7C79999418A3F37365472535EEDAB0556CC7294BA67"
    },
    {
        "uid": "3841766132",
        "password": "18D3E36B974545F818F2D2401BB40375328CBBA6F10D3650B68AA58D978C016A"
    },
    {
        "uid": "3754160088",
        "password": "AB458EA9066B93FBF0679FFCAB8FEC523A11FE5C3BC46F2C9C6DA1BF7A20B520"
    },
    {
        "uid": "3809437213",
        "password": "75534CFEBF98C4FC2137570E5C1940FCD8588D83B041571E28A8FEE15EA96BEF"
    },
    {
        "uid": "3841766132",
        "password": "18D3E36B974545F818F2D2401BB40375328CBBA6F10D3650B68AA58D978C016A"
    },
    {
        "uid": "3563549887",
        "password": "290691CDECC1950D2AA8F43DBB34C894CB09EBF92A394CB9040F4488C02107C0"
    },
    {
        "uid": "3880900897",
        "password": "C31366C533E9DB7F4910F8561D1D28F59E6268386703781CFA39D156E4120431"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3880868796",
        "password": "2A14E0ACD7E11F9D410C08CBCC25A5F3E76995A708340ADA556A6428831DC25E"
    },
    {
        "uid": "3847424229",
        "password": "B233912053D9484118D4557593E111709F73E70AE82257F416B2E8613220A635"
    },
    {
        "uid": "3796314394",
        "password": "3A2A1B554B4F78E2E965118DA1481EBF43FF598A8CEF2FC21DD62B30333B83B8"
    },
    {
        "uid": "3790758857",
        "password": "5E7B11A6D9A9F998D2ED3D677AF5B652A9D245F3725E8A5A27677AEF265D5EBB"
    },
    {
        "uid": "3790086655",
        "password": "0B6293D3785E3F3E776B6AF84096077778CA4C968683436BE1518E26DA859EC1"
    },
    {
        "uid": "3788806461",
        "password": "A43B107B761EA470AEE82D46AD1C5759AB1A8FFAE67166BE445DC1F7C5B4685F"
    },
    {
        "uid": "3751789234",
        "password": "D42ADB325DC924BE006AB56F858C26C4C7E2CECE53F24702407E4AA76E3BA32D"
    },
    {
        "uid": "3802109714",
        "password": "A49319A61CB5ED04D590A183F995D9761F0B9B3F2B7A96C479412B4F4D9AB53D"
    },
    {
        "uid": "3926886442",
        "password": "FCCA8F22A3FF867A77C92411A36D0E2711B09BCDE2378BEA91D528CF5FE07326"
    },
    {
        "uid": "3926891510",
        "password": "1A231920B086C8347B38909FBEA9C5F9144B53C10834BBBA384BBD3CFD3473D3"
    },
    {
        "uid": "3926897066",
        "password": "9E628CEE39B1FC327343801E52C9B53382EECFF66D1F73FF092FEF4C3795BFC0"
    },
    {
        "uid": "3926902294",
        "password": "694BE9F978687C30F54C75B34C185E7DFFCD63911FFC4808EF9C8C9019B3CD9B"
    },
    {
        "uid": "3926881628",
        "password": "619A17F4B625CB390C9274862C9D162C1D5BE61BA215E7A896B64A281EDBFA61"
    },
    {
        "uid": "3879895104",
        "password": "56885D62528354E50EC5F98453CB7B30C52D4A0AB0E18D83B2DD44B3FA187DFF"
    },
    {
        "uid": "3841766132",
        "password": "18D3E36B974545F818F2D2401BB40375328CBBA6F10D3650B68AA58D978C016A"
    },
    {
        "uid": "3918459050",
        "password": "D4EDD99113E6322324792365BEB39B4481C646409B2EBF0BACFA7A0D0EE8C0EF"
    },
    {
        "uid": "3929024506",
        "password": "52A76B7EA56922AA549A9358AEDD06643AA077EC89033EC331DE5F9512D06D85"
    },
    {
        "uid": "3929928012",
        "password": "8FB7E86722A869F51813DC68728D1AD67E0A2F5AB76CA1C5A70B258CA6E5672C"
    },
    {
        "uid": "3929933053",
        "password": "E866E8899BAD78014313673D60946B397382586CE60733F18123560D6B084509"
    },
    {
        "uid": "3929938459",
        "password": "08AD8B0E1A41F5DE6D5D11D12F2A7017D856800066BCD785DA81E2AC909500F9"
    },
    {
        "uid": "3929950272",
        "password": "F65919CAD3F6E9D6C5B1375A1F59219666F32C50C55D10950D71F384F3100E36"
    },
    {
        "uid": "3929958001",
        "password": "3CA2D44B997B3104AB8716D7575F639750B48E5EF9D6E05A537FC6C35DD01A27"
    },
    {
        "uid": "3929966303",
        "password": "96DBCF6108ABFF75FC6BD5D1433D439386F0AE99672A1AC7FD0D12E5A7032F35"
    },
    {
        "uid": "3929973875",
        "password": "16706016C018D62B600D74A1FA5EF5442A320D5921A831AE1B7644D9A2086FD4"
    },
    {
        "uid": "3929980699",
        "password": "092EA958F561B43FF6F2BC8ECF54D4B60F764E8C541178E1D25DC89871969921"
    },
    {
        "uid": "3929986105",
        "password": "7FB146183C29363F82E603D0AC199936D46943B124C1673AB0B27128B59AD267"
    },
    {
        "uid": "3929992126",
        "password": "D3645221F57ADB5D2601EEC7776FC1388E304BD870D86F77A1FC19C58F47083D"
    },
    {
        "uid": "3929998656",
        "password": "08A6DFD17114603059F9BC6CA52E4601FABE3E916F9EB2AF3BE87B379D8C7A23"
    },
    {
        "uid": "3930005966",
        "password": "04E53272190C1128F5E50C6FF6D68F7B74D9CA98176817982A3748219B5328AC"
    },
    {
        "uid": "3930012485",
        "password": "8131F377CC1E06B512B5F025BCF560F1919CDE221D6D220330EF635901689E27"
    },
    {
        "uid": "3930018951",
        "password": "50F5E2AC6902F49E027E3394016E946B2A92F94D98FC433DC545EB2820019746"
    },
    {
        "uid": "3930025746",
        "password": "CC3C7A50BCDAA77E1BC400A6BA03743A1A9189400C8BDC4C07282C80D90076B1"
    },
    {
        "uid": "3929067773",
        "password": "BDA7C456A63AA534516E4971034125864728AD222B9C359FF8A36BFD46662647"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3926902294",
        "password": "694BE9F978687C30F54C75B34C185E7DFFCD63911FFC4808EF9C8C9019B3CD9B"
    },
    {
        "uid": "3929080271",
        "password": "3C230ED852F2E20B374591877B8C208BA77B90439D276620C4C446E3A5829326"
    },
    {
        "uid": "3929083251",
        "password": "23FE3A8B1ADF8E3E33535A4F64472A73AEB8A3F54E49C5EEB6C6F44E27B79340"
    },
    {
        "uid": "3929063040",
        "password": "65027E309987C68B0210B70574F3482D0AFA78CDC3EBA9698B099836A42F6E8C"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3929128504",
        "password": "162DC2ACBCDAA3D2F27C233EF7C0A348B29E299D239FB82B98D3DBA73DFAE207"
    },
    {
        "uid": "3929067773",
        "password": "BDA7C456A63AA534516E4971034125864728AD222B9C359FF8A36BFD46662647"
    },
    {
        "uid": "3933316043",
        "password": "98892CC5B3FD8D95DADABE4484AA55EAA6D2CBDAB0615A31A97A671965ECB332"
    },
    {
        "uid": "3933351941",
        "password": "5AE1E25966C89CB266CD15A267DC7E15A5E61B94CD0C501AC326875B65D76B8B"
    },
    {
        "uid": "3933385590",
        "password": "4CA8EEAC226CDBABFA230039F61E187F3726A986B700DB50A6AC4A0757ADF4AA"
    },
    {
        "uid": "3933327654",
        "password": "3E1D013F912B497B7ABB1297324D51BE7D9A8FC823BEEA9C541DC2133D5E9982"
    },
    {
        "uid": "3933321650",
        "password": "62BF6EEE63A939CB2E3B0514E0621CB255126E7F40ADD6DE037999B6D686396A"
    },
    {
        "uid": "3933455843",
        "password": "65BEB0AD73EAA5C65CEEF1EB415FC0B027DE45082B5F156E179AE9D6548179D1"
    },
    {
        "uid": "3933453126",
        "password": "A7D0EA22F7CF3C4A69178765A7638F286045AC3FB41C2AC5126C0B0A7A11FC4B"
    },
    {
        "uid": "3933450103",
        "password": "A238643D66ECE05096D2C172ACE48CAADF030472FC389073484325E8362C84F3"
    },
    {
        "uid": "3933446272",
        "password": "9C689E3A51234FB25857FBEC53CF616005D41D633D6FD75DB240D20F6CC1DFED"
    },
    {
        "uid": "3933443437",
        "password": "12C9F8CF23DCCFF248FB2EFBF5E2A93970E280866568E1944956CE06E6F0D569"
    },
    {
        "uid": "3933439651",
        "password": "1E94FF1BBC213F1A9012E4083B8D85FBA52E21CA3C152B2CC3222FED6CEA7A88"
    },
    {
        "uid": "3933436070",
        "password": "5140AC28EA1E5ABF9A5570017E2A6D9F6ECBA41F17E9F6DD22C13E787424650D"
    },
    {
        "uid": "3933432251",
        "password": "B2A30AA29FCC139812238D86FE3BAE937E283ACE23D298D0E98AF2F5264ED107"
    },
    {
        "uid": "3933428593",
        "password": "3A2CD0D9A3B95B998A7FF319F12407B9AFCD6328B24EE69A70285D9EEE6BF983"
    },
    {
        "uid": "3933424648",
        "password": "A9A8F15EABE86C77ED56896D5B329B953E624988AB06D1B5380EBB42DDD6ADE1"
    },
    {
        "uid": "3933412318",
        "password": "1AA5D1AB515E75F499E773F6DE9AB8EE020AA01AA4D518A071FDCF7395D5CB39"
    },
    {
        "uid": "3933406857",
        "password": "23F62562D12A26F12860A1C13592399343BE46B850D1B698A609CE2CDC418440"
    },
    {
        "uid": "3933402547",
        "password": "7602C3108174EAB76E8A3582E5DD53E93886185DC461EF743F3DA1DEEEF196BF"
    },
    {
        "uid": "3933399030",
        "password": "9B0165A5C7390C833E20A0C7A9E8F0697288A483FB8DA6BCD2F16A57193BEC68"
    },
    {
        "uid": "3933394983",
        "password": "DBEFE188B69F6A69C4D9281149510F2161DC23F2105CC591AB9554811CEC15BA"
    },
    {
        "uid": "3933391047",
        "password": "A6AF20AF14B54B8290407D2B1D6C4727C371D63A08F29A1FC91C1DB248B4FF35"
    },
    {
        "uid": "3933381811",
        "password": "FA2C1A72AE669B40C12C36DE55F10CCCC669D7733E6F760E357EDF5834E1DFFA"
    },
    {
        "uid": "3933377550",
        "password": "5479E32CE09B533F996466CE211F73313C3E36834147AB4E951D4CB08E2223F3"
    },
    {
        "uid": "3933373443",
        "password": "408A27D368D22031CBB2960351AF6B9347E1C1D3BB98A5C0DBD4FD7357045DDD"
    },
    {
        "uid": "3933368339",
        "password": "358A6749B56C1F86989F4C38511490AEBE51BE9CD487D8F14A1B96FE63A618F4"
    },
    {
        "uid": "3933364094",
        "password": "5AF614F4736037EC0607AD151CAD9318ED7A78CD8E2515F69310E4516F96050F"
    },
    {
        "uid": "3933360301",
        "password": "22409C3EA18C2576FD65BF97C22776F432C06301BDFA1C78F22A8001F0FA9660"
    },
    {
        "uid": "3933356115",
        "password": "CA6DDAEE7F32A95D6BC17B15B8D5C59E091338B4609F25A1728720E8E4C107C4"
    },
    {
        "uid": "3933347705",
        "password": "40460123D28BAC36D13CD8C19E2692A87B265656CB31937E078B70A3B2F9DA7B"
    },
    {
        "uid": "3933332313",
        "password": "5011829C77FFD09962817F1F769768D90FAF5EB5E4FB6403AFDD55E334A89567"
    },
    {
        "uid": "3937779086",
        "password": "75A6D2B88799BEC93A3ADAAE3BDC2240CAD02D04B6B8EDC187F96681AE94852C"
    },
    {
        "uid": "3937873330",
        "password": "B24934296378DE5F3FE01E2C0FE935F09395B01032BF0034C921324BFAC44DE9"
    },
    {
        "uid": "3937874660",
        "password": "C4A8C2F5BE00A58711EB2BC18FF403B49C74D02B2180822E3123749CB1AB1C3E"
    },
    {
        "uid": "3937876771",
        "password": "81D7EE8032ED659A4C6D98ACF8EC2D50D0EAEE8C461F426A5B4E714F0F6A2346"
    },
    {
        "uid": "3937878012",
        "password": "A31991D03CE21E871509CA7C7DD088BDD7F47BB5B23D4408755F5CD079F251D7"
    },
    {
        "uid": "3937881352",
        "password": "BAD8800773EFE15D791F33325F1FFB4B8F740E09A8EF98AF292847EB21619525"
    },
    {
        "uid": "3937885798",
        "password": "73499A92D059562CB5EA7B3EC6BF0B8FB36E897C6EEDEA8ABF35467AFEC03F68"
    },
    {
        "uid": "3937887751",
        "password": "12BEC7CCFB959B426569AEECF4B38185212F0BC67B200056F25DCA35255BC250"
    },
    {
        "uid": "3937889219",
        "password": "ECD5810AB8DB278247E55B2F51E1C43BBC9C9087BF9A33A2BBC3C00E6F973160"
    },
    {
        "uid": "3937891177",
        "password": "4AA65B8B5C51B223C7AB05677C47D2799D8AD861E314C65AA07143A5BC4127BD"
    },
    {
        "uid": "3937892213",
        "password": "B6775827EB3363E067D18FDE07756AC0DD14539A34DEF7911305F1EC35F8A96C"
    },
    {
        "uid": "3937893670",
        "password": "48005D494EFB7C8563217E95DD258BF42056869D0A07B152C8E11C2B63439ED8"
    },
    {
        "uid": "3937870872",
        "password": "C7A8E1954714711A198A22FA72A1827527F2B95D3C5AC0988B75130A9B7289D6"
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
