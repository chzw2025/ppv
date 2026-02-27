def build_m3u(data):
    lines = ["#EXTM3U"]
    total = 0

    for cat in data.get("streams", []):
        category = cat.get("category", "PPV")

        for s in cat.get("streams", []):
            name = s.get("name", "Unnamed")
            iframe = s.get("iframe")
            logo = get_logo(s)

            if not iframe:
                continue

            # --- 核心修改：智能替换地址 ---
            # 自动识别 embed 类型的链接并替换为你的代理地址
            if "/embed/" in iframe:
                # 获取最后一段路径（例如 nfl-network）
                stream_id = iframe.split("/embed/")[-1]
                iframe = f"https://abc.com/stream?uri={stream_id}"
            # ---------------------------

            total += 1

            if logo:
                extinf = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{category}",{name}'
            else:
                extinf = f'#EXTINF:-1 group-title="{category}",{name}'

            lines.append(extinf)
            lines.append(iframe)

    print(f"总频道: {total}")
    return "\n".join(lines)
