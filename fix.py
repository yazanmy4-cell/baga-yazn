# mitmweb_handlers.py
# Chạy: mitmweb -s fix.py
from mitmproxy import http
import datetime
import os
import binascii
import base64
import ChooseEmote_pb2
import ChooseClothes_pb2
import LoginResNew_pb2
import GetPlayerPersonalShow_pb2
import ChooseShow_pb2
import blackboxprotobuf
import gzip
from google.protobuf.descriptor import FieldDescriptor

SERVER_HOSTS = frozenset([
    "clientbp.ppmainecoonghj.com",
    "client.ind.freefiremobile.com",
    "client.us.freefiremobile.com",
])
LOGIN_HOSTS = frozenset([
    "loginbp.ppmainecoonghj.com",
    "login.ind.freefiremobile.com",
])
ALL_HOSTS = SERVER_HOSTS | LOGIN_HOSTS

try:
    from AES import AESUtils
    aes_utils = AESUtils()
    print("AESUtils module loaded successfully")
except ImportError as e:
    print(f"AES module error: {e}")

    class DummyAESUtils:
        key_base64 = "WWcmdGMlREV1aDYlWmNeOA=="
        iv_base64 = "Nm95WkRyMjJFM3ljaGpNJQ=="

        def decrypt_aes_cbc(self, ciphertext_hex):
            print(f"Dummy decrypt: {ciphertext_hex[:50]}...")
            return bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""

        def decrypt_aes_cbc_bytes(self, data_bytes):
            print(f"Dummy decrypt bytes: {len(data_bytes)} bytes")
            return data_bytes

    aes_utils = DummyAESUtils()


# ============ CONSTANTS ============
FIXED_AVATAR_ID = 902038002
FIXED_BANNER_ID = 901000276


def _make_headers(body: bytes) -> dict:
    return {
        "vary": "Accept-Encoding",
        "date": datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "content-length": str(len(body)),
        "content-type": "application/octet-stream",
        "X-Mitmweb-Modified": "true",
    }


def octet_stream_to_hex(octet_stream):
    return binascii.hexlify(octet_stream).decode()


def hex_to_octet_stream(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str) if hex_str else b""


def debug_protobuf(data, label="Unknown"):
    try:
        msg, typedef = blackboxprotobuf.decode_message(data)
        print(f"{label} blackbox decode (full fields):")
        for k, v in sorted(msg.items()):
            kt = type(k).__name__
            if isinstance(v, bytes):
                try:
                    print(f"  ({kt}) {k}: '{v.decode('utf-8')}' (len={len(v)})")
                except Exception:
                    print(f"  ({kt}) {k}: {v.hex()[:50]}... (bytes, len={len(v)})")
            elif isinstance(v, (dict, list)):
                print(f"  ({kt}) {k}: {type(v)} (len={len(v)})")
            else:
                print(f"  ({kt}) {k}: {v}")
        return msg
    except Exception as e:
        print(f"{label} blackbox decode failed: {e}")
        return None


stored_emotes = {}
stored_banner_id = None
stored_avatar_id = None
stored_clothes_id = None
stored_clothes_hash = None
stored_slot_string = None
stored_slot_hash = None
stored_show_slot_id = None


def _safe_get(d, key, default=0):
    if d is None or not isinstance(d, dict):
        return default
    if key in d:
        return d[key]
    sk = str(key)
    if sk in d:
        return d[sk]
    try:
        ik = int(key)
        if ik in d:
            return d[ik]
    except Exception:
        pass
    return default


def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_bytes_fields(buf):
    """Parse protobuf top-level fields of wire type 2. Returns dict {field_num: bytes}."""
    fields = {}
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = read_varint(buf, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 2:
            try:
                length, pos = read_varint(buf, pos)
            except Exception:
                break
            value = buf[pos:pos + length]
            pos += length
            fields[field_num] = value
        elif wire_type == 0:
            try:
                _, pos = read_varint(buf, pos)
            except Exception:
                break
        else:
            break
    return fields


def try_decode_response_body(body: bytes, aes_utils_instance):
    raw = body
    pt = None
    try:
        msg, _ = blackboxprotobuf.decode_message(raw)
        print("Direct protobuf parse OK")
        return raw
    except Exception:
        pass
    try:
        hex_str = raw.hex()
        dec = aes_utils_instance.decrypt_aes_cbc(hex_str)
        if dec[:2] == b"\x1f\x8b":
            dec = gzip.decompress(dec)
            print("AES decrypt (no IV) + gzip OK")
        pt = dec
    except Exception as e:
        print(f"AES no IV failed: {e}")
    if not pt and len(raw) > 16:
        try:
            iv = raw[:16]
            cipher = raw[16:]
            key = base64.b64decode(aes_utils_instance.key_base64)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            cipher_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec = cipher_obj.decryptor().update(cipher) + cipher_obj.decryptor().finalize()
            pad = dec[-1]
            if 1 <= pad <= 16:
                dec = dec[:-pad]
            if dec[:2] == b"\x1f\x8b":
                dec = gzip.decompress(dec)
                print("AES IV prefix + gzip OK")
            pt = dec
        except Exception as e:
            print(f"AES IV prefix failed: {e}")
    if not pt:
        try:
            dec = aes_utils_instance.decrypt_aes_cbc_bytes(raw)
            if dec[:2] == b"\x1f\x8b":
                dec = gzip.decompress(dec)
                print("AES decrypt_bytes + gzip OK")
            pt = dec
        except Exception as e:
            print(f"AES decrypt_bytes failed: {e}")
    if not pt:
        print("No decoding succeeded, using raw")
        pt = raw
    try:
        msg, _ = blackboxprotobuf.decode_message(pt)
        print("Final protobuf parse OK on decoded data")
        return pt
    except Exception:
        print("Could not parse decoded data as protobuf")
        return raw


LOCAL_BIN_PATH = "GetPlayerPersonalShow.bin"

BLOCK_FIELDS = {
    "field_65",
    "cosmetic_skin",
    "kills",
    "field_76",
    "field_75",
    "matches_played",
    "field_48",
    "experience",
    "field_16",
    "field_17",
    "daily_challenges",
    "main_weapon",
    "field_23",
    "headshot_percentage",
    "current_rank",
    "rank",
    "profile",
    "session",
    "settings",
    "currencies",
}


def _is_repeated(field):
    try:
        return field.is_repeated
    except AttributeError:
        return field.label == FieldDescriptor.LABEL_REPEATED


def merge_msg(src, dst):
    for field in src.DESCRIPTOR.fields:
        if field.name in BLOCK_FIELDS:
            continue
        src_value = getattr(src, field.name)
        if _is_repeated(field):
            dst_list = getattr(dst, field.name)
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                while len(dst_list) < len(src_value):
                    dst_list.add()
                for i in range(len(src_value)):
                    merge_msg(src_value[i], dst_list[i])
            else:
                dst_list[:] = src_value
        else:
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                merge_msg(src_value, getattr(dst, field.name))
            else:
                setattr(dst, field.name, src_value)


def create_clan_logo_protobuf():
    """Build clan_logo message manually as bytes.
    Structure: field 4 is a map<string, int64> with 3 entries.
    Each map entry: field 1 = key(string), field 2 = value(int)
    """
    def encode_tag(field_num, wire_type):
        return encode_varint((field_num << 3) | wire_type)

    def encode_bytes_field(field_num, data):
        return encode_tag(field_num, 2) + encode_varint(len(data)) + data

    def encode_varint_field(field_num, value):
        return encode_tag(field_num, 0) + encode_varint(value)

    entries = [
        ("25375000", 205000000),
        ("25500000", 208000000),
        ("26750000", 211000000),
    ]
    msg = b""
    for key_str, val in entries:
        entry = b""
        entry += encode_bytes_field(1, key_str.encode("utf-8"))
        entry += encode_varint_field(2, val)
        msg += encode_bytes_field(4, entry)
    return msg


def encode_varint(n):
    if n < 0:
        n = (1 << 64) + n
    buf = b""
    while True:
        towrite = n & 0x7F
        n >>= 7
        if n:
            buf += bytes([towrite | 0x80])
        else:
            buf += bytes([towrite])
            break
    return buf


def encode_nested_bytes_msg(slot_str_bytes, slot_hash_bytes):
    nested = b""
    nested += b"\x3A" + encode_varint(len(slot_str_bytes)) + slot_str_bytes
    nested += b"\x4A" + encode_varint(len(slot_hash_bytes)) + slot_hash_bytes
    msg = b"\x0A" + encode_varint(len(nested)) + nested
    return msg


def request(flow: http.HTTPFlow) -> None:
    global stored_emotes, stored_banner_id, stored_avatar_id, stored_clothes_id, stored_clothes_hash, stored_slot_string, stored_slot_hash, stored_show_slot_id
    host = flow.request.host
    path = flow.request.path
    method = flow.request.method

    if host in ALL_HOSTS and path == "/ChooseEmote" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE EMOTE REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            print(f"Hex: {req_body.hex()}")
            print("Decrypting with AESUtils.decrypt_aes_cbc()...")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            print(f"Hex: {decrypted_data.hex()}")
            debug_msg = debug_protobuf(decrypted_data, "Request protobuf")
            sub = _safe_get(debug_msg, 6, None)
            processed = 0
            if sub:
                if isinstance(sub, list):
                    print(f"Multi-slot mode: processing {len(sub)} actions")
                    for slot_dict in sub:
                        if isinstance(slot_dict, dict):
                            raw_slot = _safe_get(slot_dict, 1, 0)
                            raw_item = _safe_get(slot_dict, 2, 0)
                            try:
                                slot = int(raw_slot)
                            except Exception:
                                slot = 0
                            try:
                                item_id = int(raw_item)
                            except Exception:
                                item_id = 0
                            if slot > 0:
                                if item_id > 0:
                                    old_item = stored_emotes.get(slot, None)
                                    stored_emotes[slot] = item_id
                                    if old_item is not None:
                                        print(f"Updated slot {slot} from {old_item} to {item_id}")
                                    else:
                                        print(f"Added new emote slot {slot} with item_id {item_id}")
                                else:
                                    if slot in stored_emotes:
                                        del stored_emotes[slot]
                                        print(f"Removed slot {slot} (unequip)")
                                processed += 1
                        else:
                            print(f"Invalid slot_dict: {type(slot_dict)}")
                elif isinstance(sub, dict):
                    print("Single-slot mode")
                    raw_slot = _safe_get(sub, 1, 0)
                    raw_item = _safe_get(sub, 2, 0)
                    try:
                        slot = int(raw_slot)
                    except Exception:
                        slot = 0
                    try:
                        item_id = int(raw_item)
                    except Exception:
                        item_id = 0
                    if slot > 0:
                        if item_id > 0:
                            old_item = stored_emotes.get(slot, None)
                            stored_emotes[slot] = item_id
                            if old_item is not None:
                                print(f"Updated slot {slot} from {old_item} to {item_id}")
                            else:
                                print(f"Added new emote slot {slot} with item_id {item_id}")
                        else:
                            if slot in stored_emotes:
                                del stored_emotes[slot]
                                print(f"Removed slot {slot} (unequip)")
                        processed += 1
                else:
                    print(f"Unexpected sub type: {type(sub)}")
            print(f"Processed {processed} slot actions")
        except Exception as e:
            print(f"Error processing request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")

    if host in ALL_HOSTS and path == "/ChooseBanner" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE BANNER REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            print(f"Hex: {req_body.hex()}")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            debug_msg = debug_protobuf(decrypted_data, "ChooseBanner Request protobuf")
            raw_banner = _safe_get(debug_msg, 1, None)
            if raw_banner is None:
                print("Scanning all fields for potential banner_id...")
                for k, v in debug_msg.items():
                    if isinstance(v, int) and v > 900000000:
                        raw_banner = v
                        print(f"Found candidate in field {k}: {v}")
                        break
            if raw_banner is not None:
                try:
                    stored_banner_id = int(raw_banner)
                    print(f"Set banner_id to {stored_banner_id}")
                except Exception:
                    print(f"Invalid banner_id {raw_banner}")
        except Exception as e:
            print(f"Error processing ChooseBanner request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")

    if host in ALL_HOSTS and path == "/ChooseHeadPic" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE HEAD PIC REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            debug_msg = debug_protobuf(decrypted_data, "ChooseHeadPic Request protobuf")
            raw_avatar = _safe_get(debug_msg, 1, None)
            if raw_avatar is not None:
                try:
                    stored_avatar_id = int(raw_avatar)
                    print(f"Set avatar_id to {stored_avatar_id}")
                except Exception:
                    print(f"Invalid avatar_id {raw_avatar}")
            else:
                print("No valid avatar_id in field 1")
        except Exception as e:
            print(f"Error processing ChooseHeadPic request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")

    if host in ALL_HOSTS and path == "/ChangeClothes" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHANGE CLOTHES REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            print(f"Hex: {req_body.hex()}")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            print(f"Hex: {decrypted_data.hex()}")
            debug_msg = debug_protobuf(decrypted_data, "ChangeClothes Request protobuf")
            raw_id = _safe_get(debug_msg, 1, None)
            raw_hash = _safe_get(debug_msg, 2, None)
            if raw_id is not None:
                try:
                    stored_clothes_id = int(raw_id)
                    print(f"Stored clothes_id: {stored_clothes_id}")
                except Exception:
                    print(f"Invalid clothes_id {raw_id}")
            if raw_hash is not None:
                try:
                    if isinstance(raw_hash, bytes):
                        stored_clothes_hash = binascii.hexlify(raw_hash).decode("ascii")
                    else:
                        stored_clothes_hash = str(raw_hash)
                    print(f"Stored clothes_hash: {stored_clothes_hash}")
                except Exception:
                    print(f"Invalid clothes_hash {raw_hash}")
        except Exception as e:
            print(f"Error processing ChangeClothes request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")

    if host in ALL_HOSTS and path == "/ChooseSlotsAndShow" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE SLOTS AND SHOW REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            print(f"Hex: {req_body.hex()}")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            print(f"Hex: {decrypted_data.hex()}")

            fields = parse_bytes_fields(decrypted_data)
            raw_slot_str = fields.get(1)
            raw_slot_hash = fields.get(2)

            if raw_slot_str is not None:
                stored_slot_string = binascii.hexlify(raw_slot_str).decode("ascii").lower()
                print(f"Stored slot_string: {stored_slot_string[:80]}... (len={len(raw_slot_str)} bytes)")
            else:
                print("No field 1 (slot_string) found")

            if raw_slot_hash is not None:
                stored_slot_hash = binascii.hexlify(raw_slot_hash).decode("ascii").lower()
                print(f"Stored slot_hash: {stored_slot_hash} (len={len(raw_slot_hash)} bytes)")
            else:
                print("No field 2 (slot_hash) found")
        except Exception as e:
            print(f"Error processing ChooseSlotsAndShow request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")

    if host in ALL_HOSTS and path == "/ChooseShow" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE SHOW REQUEST - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            req_body = flow.request.content
            print(f"Raw request: {len(req_body)} bytes")
            ciphertext_hex = req_body.hex()
            decrypted_data = aes_utils.decrypt_aes_cbc(ciphertext_hex)
            print(f"Decrypted: {len(decrypted_data)} bytes")
            print(f"Hex: {decrypted_data.hex()}")

            fields = parse_bytes_fields(decrypted_data)
            raw_show_id = fields.get(1)

            if raw_show_id is not None:
                if len(raw_show_id) == 0:
                    stored_show_slot_id = ""
                    print("Stored empty show_slot_id")
                else:
                    stored_show_slot_id = binascii.hexlify(raw_show_id).decode("ascii").lower()
                    print(f"Stored show_slot_id: {stored_show_slot_id} (len={len(raw_show_id)} bytes)")
            else:
                print("No field 1 (show_slot_id) found")
        except Exception as e:
            print(f"Error processing ChooseShow request: {e}")
            import traceback
            traceback.print_exc()
        print(f"{'=' * 70}")


def response(flow: http.HTTPFlow) -> None:
    global stored_emotes, stored_banner_id, stored_avatar_id, stored_clothes_id, stored_clothes_hash, stored_slot_string, stored_slot_hash, stored_show_slot_id
    host = flow.request.host
    path = flow.request.path
    method = flow.request.method

    if host in ALL_HOSTS and path == "/ChooseEmote" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE EMOTE RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            res = ChooseEmote_pb2.ChooseProfileRes()
            profile_info = ChooseEmote_pb2.ProfileInfo()
            profile_info.banner_id_primary = FIXED_BANNER_ID
            print(f"Using FIXED banner_id_primary: {FIXED_BANNER_ID}")
            profile_info.avatar_id = FIXED_AVATAR_ID
            print(f"Using FIXED avatar_id: {FIXED_AVATAR_ID}")
            profile_info.banner_id_override = 904990072
            equipped = ChooseEmote_pb2.ProfileList()
            if stored_emotes:
                for slot, item_id in sorted(stored_emotes.items()):
                    slot_msg = equipped.slot.add()
                    slot_msg.slot = int(slot)
                    slot_msg.item_id = int(item_id)
                print(f"Equipped emotes: {len(stored_emotes)} slots")
            else:
                print("No stored emotes")
            profile_info.equipped.CopyFrom(equipped)
            res.info.CopyFrom(profile_info)
            proto_bytes = res.SerializeToString()
            debug_protobuf(proto_bytes, "Response protobuf")
            body = proto_bytes
        except Exception as e:
            print(f"Error creating response: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/ChooseBanner" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE BANNER RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            simple_res = ChooseEmote_pb2.ChooseProfileRes()
            profile_info = ChooseEmote_pb2.ProfileInfo()
            profile_info.banner_id_primary = FIXED_BANNER_ID
            simple_res.info.CopyFrom(profile_info)
            proto_bytes = simple_res.SerializeToString()
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/ChooseHeadPic" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE HEAD PIC RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            simple_res = ChooseEmote_pb2.ChooseProfileRes()
            profile_info = ChooseEmote_pb2.ProfileInfo()
            profile_info.avatar_id = FIXED_AVATAR_ID
            simple_res.info.CopyFrom(profile_info)
            proto_bytes = simple_res.SerializeToString()
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/ChangeClothes" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHANGE CLOTHES RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            body = b""
            default_item_id = 102000007
            default_hash = "9b98e9609ba1e361db9ca6619bbcd16480c38566"
            item_id = stored_clothes_id if stored_clothes_id is not None else default_item_id
            auth_token = stored_clothes_hash if stored_clothes_hash else default_hash
            res = ChooseClothes_pb2.ChooseClothesRes()
            data = ChooseClothes_pb2.ResponseData()
            data.item_id = item_id
            data.auth_token = auth_token
            print(f"Using item_id: {data.item_id}")
            print(f"Using auth_token: {data.auth_token}")
            res.data.CopyFrom(data)
            proto_bytes = res.SerializeToString()
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/ChooseSlotsAndShow" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE SLOTS AND SHOW RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            body = b""
            default_slot_string = (
                "000081e9c4af0300000000000000000000b7a0cbb003"
                "00000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000"
            )
            default_slot_hash = "b7a0cbb003"
            slot_string = stored_slot_string if stored_slot_string else default_slot_string
            slot_hash = stored_slot_hash if stored_slot_hash else default_slot_hash
            print(f"Using slot_string: {slot_string[:80]}...")
            print(f"Using slot_hash: {slot_hash}")

            if not all(c in "0123456789abcdef" for c in slot_string):
                print(f"WARNING: slot_string is not valid hex, using default")
                slot_string = default_slot_string

            slot_str_bytes = bytes.fromhex(slot_string)
            slot_hash_bytes = bytes.fromhex(slot_hash)
            proto_bytes = encode_nested_bytes_msg(slot_str_bytes, slot_hash_bytes)
            debug_protobuf(proto_bytes, "ChooseSlotsAndShow Response")
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/ChooseShow" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"CHOOSE SHOW RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            body = b""
            default_show_slot_id = "f7ddd0b003"
            show_slot_id = stored_show_slot_id if stored_show_slot_id is not None else default_show_slot_id
            if show_slot_id == "":
                inner_data_show_slot_id = b""
                print("Using empty show_slot_id")
            else:
                if isinstance(show_slot_id, str) and all(c in "0123456789abcdef" for c in show_slot_id.lower()):
                    inner_data_show_slot_id = bytes.fromhex(show_slot_id)
                    print(f"Using show_slot_id: {show_slot_id}")
                else:
                    inner_data_show_slot_id = bytes.fromhex(default_show_slot_id)
                    print(f"Invalid, using default {default_show_slot_id}")
            res = ChooseShow_pb2.ChooseShowResponse()
            res.data.show_slot_id = inner_data_show_slot_id
            proto_bytes = res.SerializeToString()
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/GetLoginData" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"GET LOGIN DATA RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            original_body = flow.response.content if flow.response else b""
            print(f"Original response: {len(original_body)} bytes")
            decoded_body = try_decode_response_body(original_body, aes_utils)
            res = LoginResNew_pb2.LoginRes()
            res.ParseFromString(decoded_body)
            print("Original LoginRes fields:")
            try:
                print(f" - uf_9: {getattr(res, 'uf_9', 'N/A')}")
                print(f" - uf_10: {getattr(res, 'uf_10', 'N/A')}")
                print(f" - level: {getattr(res, 'level', 'N/A')}")
                print(f" - exp: {getattr(res, 'exp', 'N/A')}")
            except Exception:
                pass
            res.uf_9 = 100000000
            res.uf_10 = 100000000
            res.level = 1337
            res.exp = 99999999
            res.role = 16384
            res.badge_id = 1001000091
            proto_bytes = res.SerializeToString()
            print("Hacked LoginRes fields set")
            body = proto_bytes
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            body = flow.response.content if flow.response else b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/GetPlayerPersonalShow" and method == "POST":
        print(f"\n{'=' * 70}")
        print(f"GET PLAYER PERSONAL SHOW RESPONSE - {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'=' * 70}")
        try:
            original_body = flow.response.content if flow.response else b""
            print(f"Original response: {len(original_body)} bytes")
            decoded_original = try_decode_response_body(original_body, aes_utils)
            server_ok = len(decoded_original) > 4
            if server_ok:
                try:
                    server_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
                    server_msg.ParseFromString(decoded_original)
                    print("Parsed server response with pb2")
                except Exception:
                    print("Server response not valid protobuf")
                    server_ok = False
            body = original_body
            if os.path.exists(LOCAL_BIN_PATH):
                with open(LOCAL_BIN_PATH, "rb") as f:
                    bin_raw = f.read()
                print(f"Loaded .bin file: {len(bin_raw)} bytes")
                decoded_bin = try_decode_response_body(bin_raw, aes_utils)
                local_msg = GetPlayerPersonalShow_pb2.GetPlayerPersonalShow()
                try:
                    local_msg.ParseFromString(decoded_bin)
                    print("Parsed .bin with pb2")
                except Exception as parse_e:
                    print(f"Failed to parse .bin: {parse_e}")
                    if server_ok:
                        body = decoded_original
                else:
                    if server_ok:
                        merge_msg(server_msg, local_msg)
                        print("Merged server fields")
                    updated = False
                    if local_msg.players:
                        local_msg.players[0].level = 1337
                        print("Set level to 1337")
                        updated = True
                        local_msg.players[0].title_id = FIXED_AVATAR_ID
                        print(f"Set title_id to {FIXED_AVATAR_ID}")
                        local_msg.players[0].clan_id = FIXED_BANNER_ID
                        print(f"Set clan_id to {FIXED_BANNER_ID}")
                        local_msg.players[0].current_avatar = FIXED_AVATAR_ID
                        print(f"Set current_avatar to {FIXED_AVATAR_ID}")

                        print("Processing clans list:")
                        if hasattr(local_msg, "clans"):
                            del local_msg.clans[:]
                            new_clan = local_msg.clans.add()
                            new_clan.clan_id = FIXED_BANNER_ID
                            new_clan.member_count = 50
                            print(f"Added clan ID {FIXED_BANNER_ID}")
                            clan_logo_bytes = create_clan_logo_protobuf()
                            new_clan.clan_logo = clan_logo_bytes
                            print(f"Set clan_logo ({len(clan_logo_bytes)} bytes)")
                        else:
                            print("No 'clans' field")
                    elif local_msg.HasField("detailed_player"):
                        local_msg.detailed_player.level = 1337
                        local_msg.detailed_player.title_id = FIXED_AVATAR_ID
                        local_msg.detailed_player.clan_id = FIXED_BANNER_ID
                        local_msg.detailed_player.current_avatar = FIXED_AVATAR_ID
                        print("Updated detailed_player fields")
                        if hasattr(local_msg, "clans"):
                            del local_msg.clans[:]
                            new_clan = local_msg.clans.add()
                            new_clan.clan_id = FIXED_BANNER_ID
                            new_clan.member_count = 50
                            clan_logo_bytes = create_clan_logo_protobuf()
                            new_clan.clan_logo = clan_logo_bytes
                            print("Set clan with logo")
                    body = local_msg.SerializeToString()
                    print(f"Modified .bin serialized: {len(body)} bytes")
            else:
                print("GetPlayerPersonalShow.bin not found")
                body = decoded_original
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            body = flow.response.content if flow.response else b""
        flow.response = http.Response.make(200, body, _make_headers(body))
        print(f"Sent ({len(body)} bytes)")
        print(f"{'=' * 70}\n")

    if host in ALL_HOSTS and path == "/GetBackpack" and method == "POST":
        print(f"\nGetBackpack - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetBackpack.bin"):
                with open("GetBackpack.bin", "rb") as f:
                    body = f.read()
                print(f"Loaded {len(body)} bytes")
            else:
                body = b""
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))

    if host in ALL_HOSTS and path == "/GetPrimeAccountInfo" and method == "POST":
        print(f"\nGetPrimeAccountInfo - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetPrimeAccountInfo.bin"):
                with open("GetPrimeAccountInfo.bin", "rb") as f:
                    body = f.read()
                print(f"Loaded {len(body)} bytes")
            else:
                body = b""
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))

    if host in ALL_HOSTS and path == "/GetVipCardInfo" and method == "POST":
        print(f"\nGetVipCardInfo - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetVipCardInfo.bin"):
                with open("GetVipCardInfo.bin", "rb") as f:
                    body = f.read()
                print(f"Loaded {len(body)} bytes")
            else:
                body = b""
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))

    if host in ALL_HOSTS and path == "/GetUnlockedFittingSlots" and method == "POST":
        print(f"\nGetUnlockedFittingSlots - {datetime.datetime.now().strftime('%H:%M:%S')}")
        try:
            if os.path.exists("GetUnlockedFittingSlots.bin"):
                with open("GetUnlockedFittingSlots.bin", "rb") as f:
                    body = f.read()
                print(f"Loaded {len(body)} bytes")
            else:
                body = b""
        except Exception as e:
            print(f"Error: {e}")
            body = b""
        flow.response = http.Response.make(200, body, _make_headers(body))

    if host in ALL_HOSTS and path == "/UnlockProfile" and method == "POST":
        flow.response = http.Response.make(200, b"", _make_headers(b""))

    if host in ALL_HOSTS and path == "/SetAccountBadge" and method == "POST":
        flow.response = http.Response.make(200, b"", _make_headers(b""))

    if host in ALL_HOSTS and path == "/UsePlayItemLimitedCards" and method == "POST":
        flow.response = http.Response.make(200, b"", _make_headers(b""))


def load(loader):
    print("MitmProxy Handler Loaded!")


if __name__ == "__main__":
    print("\nScript ready! Run with: mitmweb -s mitmweb_handlers.py")