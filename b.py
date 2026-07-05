import requests
from datetime import datetime
import re

# 配置信息
API_URL = "https://api.ppv.st/api/streams"
OUTPUT_NEW = "PPV_IFRAME.m3u8"
OUTPUT_ORIG = "example.m3u8"
NEW_PREFIX = "https://abc.com/stream?uri="

# 补全了 Referer 和 Origin 以防止被屏蔽
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": "https://ppv.to/",
    "Origin": "https://ppv.to/"
}

def get_data():
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

def format_name(raw_name, start_time_str):
    """提取并格式化时间标签"""
    # 简单的清理：如果原始名字里已经有日期，先移除
    clean_name = re.sub(r'\[\d{2}-\d{2}\s\d{2}:\d{2}\]\s*', '', raw_name)
    
    # 尝试解析 API 返回的时间字符串
    try:
        if start_time_str:
            dt = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M:%SZ")
            return f"[{dt.strftime('%m-%d %H:%M')}] {clean_name}"
    except:
        pass
    return clean_name

def generate_files(data):
    lines_new = ["#EXTM3U"]
    lines_orig = ["#EXTM3U"]
    total = 0

    for cat in data.get("streams", []):
        category = cat.get("category", "PPV")
        for s in cat.get("streams", []):
            raw_name = s.get("name", "Unnamed")
            # 假设 API 结构中包含 startTime 字段，若无则传 None
            start_time = s.get("startTime") 
            name = format_name(raw_name, start_time) # 应用格式化[cite: 1]
            raw_url = s.get("iframe", "")
            logo = s.get("poster") or s.get("logo") or ""

            if not raw_url:
                continue
            
            total += 1
            
            # 1. 原始版本[cite: 1]
            orig_url = raw_url
            
            # 2. 替换版本[cite: 1]
            if "/embed/" in raw_url:
                stream_id = raw_url.split("/embed/")[-1]
                new_url = f"{NEW_PREFIX}{stream_id}"
            else:
                new_url = raw_url

            extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{name}' if logo else f'#EXTINF:-1 group-title="{category}",{name}'

            lines_new.extend([extinf, new_url])
            lines_orig.extend([extinf, orig_url])

    with open(OUTPUT_NEW, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_new))
    with open(OUTPUT_ORIG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_orig))

    print(f"处理完成！频道总数: {total}")

if __name__ == "__main__":
    main_data = get_data()
    if main_data and "streams" in main_data:
        generate_files(main_data)
