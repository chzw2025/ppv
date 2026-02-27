import requests
from datetime import datetime

# 配置信息
API_URL = "https://api.ppv.to/api/streams"
OUTPUT_NEW = "PPV_IFRAME.m3u8"   # 替换成 abc.com 的文件
OUTPUT_ORIG = "example.m3u8"     # 原始文件
NEW_PREFIX = "https://abc.com/stream?uri="

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def get_data():
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

def get_logo(stream):
    return stream.get("poster") or stream.get("logo") or ""

def generate_files(data):
    lines_new = ["#EXTM3U"]
    lines_orig = ["#EXTM3U"]
    total = 0

    for cat in data.get("streams", []):
        category = cat.get("category", "PPV")
        for s in cat.get("streams", []):
            name = s.get("name", "Unnamed")
            raw_url = s.get("iframe", "") # 获取最原始的链接
            logo = get_logo(s)

            if not raw_url:
                continue
            
            total += 1
            
            # --- 分别处理两个版本的 URL ---
            # 1. 原始版本：直接使用 API 返回的 raw_url
            orig_url = raw_url
            
            # 2. 替换版本：基于 raw_url 进行处理
            if "/embed/" in raw_url:
                stream_id = raw_url.split("/embed/")[-1]
                new_url = f"{NEW_PREFIX}{stream_id}"
            else:
                new_url = raw_url

            # 构建 M3U 信息行 (两边通用)
            extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{name}' if logo else f'#EXTINF:-1 group-title="{category}",{name}'

            # 存入替换版列表
            lines_new.append(extinf)
            lines_new.append(new_url)
            
            # 存入原始版列表
            lines_orig.append(extinf)
            lines_orig.append(orig_url)

    # 写入文件
    with open(OUTPUT_NEW, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_new))
    
    with open(OUTPUT_ORIG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_orig))

    print(f"处理完成！频道总数: {total}")

def main():
    data = get_data()
    if data and "streams" in data:
        generate_files(data)
        print("PPV_IFRAME.m3u8 (替换版) 已生成")
        print("example.m3u8 (原始版) 已生成")
    else:
        print("获取 API 失败")

if __name__ == "__main__":
    main()
