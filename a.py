import requests
from datetime import datetime

# 配置信息
API_URL = "https://api.ppv.to/api/streams"
OUTPUT = "PPV_IFRAME.m3u8"
NEW_PREFIX = "https://abc.com/stream?uri="

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def get_data():
    """获取 API 数据"""
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            print(f"API请求失败，状态码: {r.status_code}")
            return None
        return r.json()
    except Exception as e:
        print(f"网络请求发生异常: {e}")
        return None

def get_logo(stream):
    """从多个可能字段中提取频道图标"""
    return (
        stream.get("poster")
        or stream.get("logo")
        or stream.get("image")
        or stream.get("thumbnail")
        or ""
    )

def build_m3u(data):
    """将 JSON 转换为 M3U 格式，并处理链接替换"""
    lines = ["#EXTM3U"]
    total = 0

    # 遍历所有分类
    for cat in data.get("streams", []):
        category = cat.get("category", "PPV")

        # 遍历分类下的每个流
        for s in cat.get("streams", []):
            name = s.get("name", "Unnamed")
            iframe_url = s.get("iframe", "")
            logo = get_logo(s)

            if not iframe_url:
                continue

            # --- 核心逻辑：地址转换 ---
            # 如果链接包含 /embed/，则提取最后一段 ID 并拼接新前缀
            if "/embed/" in iframe_url:
                stream_id = iframe_url.split("/embed/")[-1]
                final_url = f"{NEW_PREFIX}{stream_id}"
            else:
                # 如果不符合 embed 格式，则保持原样或根据需要处理
                final_url = iframe_url

            total += 1

            # 构建 M3U 标准行
            if logo:
                extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{name}'
            else:
                extinf = f'#EXTINF:-1 group-title="{category}",{name}'

            lines.append(extinf)
            lines.append(final_url)

    print(f"处理完成，共计频道: {total}")
    return "\n".join(lines)

def main():
    print("=== PPV M3U 转换工具 ===")
    print(f"当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    data = get_data()
    if not data or "streams" not in data:
        print("未能获取到有效的 API 数据，程序退出。")
        return

    m3u_content = build_m3u(data)

    try:
        with open(OUTPUT, "w", encoding="utf-8") as f:
            f.write(m3u_content)
        print(f"文件已成功保存至: {OUTPUT}")
    except Exception as e:
        print(f"文件保存失败: {e}")

if __name__ == "__main__":
    main()
