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
            print(f"API请求失败: {r.status_code}")
            return None
        return r.json()
    except Exception as e:
        print(f"网络异常: {e}")
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
            iframe_url = s.get("iframe", "")
            logo = get_logo(s)

            if not iframe_url:
                continue
            
            total += 1
            
            # 处理地址：一个是原始地址，一个是替换后的地址
            orig_url = iframe_url
            if "/embed/" in iframe_url:
                stream_id = iframe_url.split("/embed/")[-1]
                new_url = f"{NEW_PREFIX}{stream_id}"
            else:
                new_url = iframe_url

            # 构建 M3U 信息
            extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{name}' if logo else f'#EXTINF:-1 group-title="{category}",{name}'

            # 分别存入两个列表
            lines_new.append(extinf)
            lines_new.append(new_url)
            
            lines_orig.append(extinf)
            lines_orig.append(orig_url)

    # 写入替换后的文件
    with open(OUTPUT_NEW, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_new))
    
    # 写入原始备份文件
    with open(OUTPUT_ORIG, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_orig))

    print(f"处理完成，共计频道: {total}")

def main():
    print(f"开始任务: {datetime.now()}")
    data = get_data()
    if data and "streams" in data:
        generate_files(data)
        print(f"已生成: {OUTPUT_NEW} (替换版)")
        print(f"已生成: {OUTPUT_ORIG} (原始版)")

if __name__ == "__main__":
    main()
