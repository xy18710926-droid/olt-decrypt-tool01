import json
import base64
import string
import itertools
import os
import csv
from Crypto.Cipher import DES

# 穷举掩码时的常用字符集
CHAR_SET = string.digits + string.ascii_lowercase + string.ascii_uppercase

def des_decrypt(ciphertext_b64, key_str):
    """标准 DES ECB 解密并去除填充"""
    try:
        key_bytes = key_str.encode('utf-8')[:8]
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted_raw = cipher.decrypt(base64.b64decode(ciphertext_b64))
        
        padding_len = decrypted_raw[-1]
        if 1 <= padding_len <= 8:
            decrypted_raw = decrypted_raw[:-padding_len]
        return decrypted_raw.decode('utf-8', errors='ignore')
    except Exception:
        return None

def crack_and_decrypt(sn_mac, DESN):
    """通过碰撞穷举 **** 掩码部分"""
    if "****" not in sn_mac:
        return des_decrypt(DESN, sn_mac)
        
    prefix, suffix = sn_mac.split("****")
    total_len = 10 if prefix.startswith('j') else 12
    mask_len = total_len - len(prefix) - len(suffix)
    if mask_len <= 0:
        mask_len = 4
        
    for guess in itertools.product(CHAR_SET, repeat=mask_len):
        guess_str = "".join(guess)
        possible_sn = f"{prefix}{guess_str}{suffix}"
        result = des_decrypt(DESN, possible_sn)
        if result == possible_sn:
            return result
    return None

if __name__ == "__main__":
    input_file = "data.json"
    output_file = "解密结果表.csv"
    
    print("==================================================")
    print("      中兴 OLT C600 DESN 自动化批量解密工具       ")
    print("==================================================")
    
    # 检测同目录下是否存在配置文件
    if not os.path.exists(input_file):
        print(f"\n❌ 错误：未在当前目录下找到【{input_file}】文件！")
        print("💡 使用方法：请在程序同目录下新建 data.json，将抓包的 JSON 响应粘贴进去。")
        input("\n按任意键退出程序...")
        exit()
        
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # 兼容处理：支持抓包带 HTTP 头的原始数据，自动定位真正的 JSON 块
            content = f.read().strip()
            if "{" in content:
                content = content[content.find("{") : content.rfind("}") + 1]
            raw_data = json.loads(content)
    except Exception as e:
        print(f"\n❌ JSON 文件解析失败，请检查格式是否正确！错误信息: {e}")
        input("\n按任意键退出程序...")
        exit()

    ont_list = raw_data.get("ontState", [])
    if not ont_list:
        # 如果外层还有一层包裹，尝试自动兼容
        if "result" not in raw_data and len(raw_data.keys()) == 1:
            first_key = list(raw_data.keys())[0]
            ont_list = raw_data[first_key].get("ontState", [])
            
    if not ont_list:
        print("\n❌ 错误：JSON 数据中未找到有效的 [ontState] 设备列表！")
        input("\n按任意键退出程序...")
        exit()

    print(f"\n[+] 成功加载数据，检测到设备总数: {len(ont_list)} 台。开始爆破加解密...")
    print(f"{'ONU ID':<8}{'原始掩码 SN':<16}{'解密还原真实 SN':<20}{'当前状态':<10}")
    print("-" * 65)

    results = []
    success_count = 0
    
    for ont in ont_list:
        onuid = ont.get("ONUID", "")
        sn_mac = ont.get("SN_MAC", "")
        desn = ont.get("DESN", "")
        status = ont.get("OnlineState", "")
        last_off = ont.get("LASTOFFTIME", "")
        auth_mode = ont.get("AUTH", "")
        
        real_sn = crack_and_decrypt(sn_mac, desn)
        
        if real_sn:
            success_count += 1
            print(f"{onuid:<8}{sn_mac:<16}{real_sn:<20}{status:<10}")
            results.append([onuid, sn_mac, real_sn, status, auth_mode, last_off, "解密成功"])
        else:
            print(f"{onuid:<8}{sn_mac:<16}{'❌ 匹配失败':<20}{status:<10}")
            results.append([onuid, sn_mac, "无法解密", status, auth_mode, last_off, "Key不匹配或非标密文"])

    # 导出为 Excel 兼容的 CSV 报表
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as cf:
            writer = csv.writer(cf)
            writer.writerow(["ONU ID", "原始掩码 SN", "解密还原真实 SN", "在线状态", "认证类型", "最后下线时间", "解密状态"])
            writer.writerows(results)
        print("-" * 65)
        print(f"[√] 任务完成！成功率: {success_count}/{len(ont_list)}")
        print(f"[√] 完整解密报表已成功导出至同目录下的: 【{output_file}】")
    except Exception as e:
        print(f"\n⚠️ 报表保存失败（可能文件被 Excel 占用了）: {e}")

    input("\n处理完毕，按任意键关闭窗口...")
