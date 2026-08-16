import requests
from datetime import datetime, timezone, timedelta

# 配置信息
API_URL = "https://api.ppv.st/api/streams"
OUTPUT_NEW = "PPV_IFRAME_PROXY.m3u8"   # 替换成 abc.com 的文件
#OUTPUT_ORIG = "example.m3u8"     # # 原始文件（已注释，不再重复生成）
NEW_PREFIX = "https://abc.com/stream2?uri="

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def get_data():
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        print(f"请求 API 异常: {e}")
        return None

def get_logo(stream):
    return stream.get("poster") or stream.get("logo") or ""

def generate_files(data):
    lines_new = ["#EXTM3U"]
    lines_orig = ["#EXTM3U"]
    total = 0

    # 设定北京时间 (UTC+8) 时区，避免 GitHub Actions 默认 UTC 导致时间慢 8 小时
    bj_tz = timezone(timedelta(hours=8))

    for cat in data.get("streams", []):
        category = cat.get("category", "PPV")
        for s in cat.get("streams", []):
            name = s.get("name", "Unnamed")
            raw_url = s.get("iframe", "")
            logo = get_logo(s)
            starts_at = s.get("starts_at")

            if not raw_url:
                continue
            
            total += 1

            # --- 安全转换开播时间 (北京时间) ---
            time_tag = ""
            if starts_at:
                try:
                    ts = int(starts_at)
                    dt = datetime.fromtimestamp(ts, tz=bj_tz)
                    time_tag = dt.strftime("[%m-%d %H:%M] ")
                except (ValueError, TypeError):
                    time_tag = ""
            
            display_name = f"{time_tag}{name}"
            
            # --- 处理播放链接 ---
            orig_url = raw_url
            if "/embed/" in raw_url:
                stream_id = raw_url.split("/embed/")[-1]
                new_url = f"{NEW_PREFIX}{stream_id}"
            else:
                new_url = raw_url

            # 构建 M3U 信息行
            if logo:
                extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{display_name}'
            else:
                extinf = f'#EXTINF:-1 group-title="{category}",{display_name}'

            lines_new.append(extinf)
            lines_new.append(new_url)
            
            lines_orig.append(extinf)
            lines_orig.append(orig_url)

    # 写入文件
    with open(OUTPUT_NEW, "w", encoding="utf-8") as f:
        f.write("\n".join(lines_new))
    
    #with open(OUTPUT_ORIG, "w", encoding="utf-8") as f:  # 原始文件（已注释，不再重复生成）
        #f.write("\n".join(lines_orig))      # 原始文件（已注释，不再重复生成）

    print(f"处理完成！频道总数: {total}")

def main():
    data = get_data()
    if data and "streams" in data:
        generate_files(data)
        print("PPV_IFRAME.m3u8 (带时间/替换版) 已生成")
        print("example.m3u8 (带时间/原始版) 已生成")
    else:
        print("获取 API 失败或数据为空")

if __name__ == "__main__":
    main()
