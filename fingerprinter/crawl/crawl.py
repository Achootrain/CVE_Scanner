import asyncio
import json
import os
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, CacheMode

async def main():
    # 1. Đọc danh sách URL từ file targets.txt
    input_file = "targets.txt"
    if not os.path.exists(input_file):
        print(f"Lỗi: Không tìm thấy file {input_file}")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        # Đọc từng dòng, loại bỏ khoảng trắng dư thừa và bỏ qua dòng trống
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print("Danh sách URL trống.")
        return

    print(f"Đang chuẩn bị crawl {len(urls)} URLs...")

    # 2. Cấu hình crawler
    cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS)
    
    async with AsyncWebCrawler() as crawler:
        # arun_many sẽ xử lý danh sách URL một cách bất đồng bộ
        results = await crawler.arun_many(urls, config=cfg)

    # 3. Lưu kết quả vào file kết quả (ví dụ: results_output.jsonl)
    output_file = "results_output.jsonl"
    with open(output_file, "w", encoding="utf-8") as f:
        for r in results:
            if r.success:
                record = {
                    "url": r.url,
                    "html": r.html,
                    "headers": dict(r.response_headers or {}),
                    "status_code": r.status_code,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            else:
                print(f"Crawl thất bại: {r.url} - Lỗi: {r.error_message}")

    print(f"Đã hoàn thành! Kết quả được lưu tại {output_file}")

if __name__ == "__main__":
    asyncio.run(main())