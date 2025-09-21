import sys
import logging
import json
from aiohttp import web
import asyncio

from model_total import ModelTotal

logger = logging.getLogger(__name__)

URL = "http://localhost:8000/"

async def serve_file(request, file_to_serve):
    try:
        logger.info("Serving file")
        content = open(file_to_serve, mode="rb").read()
        return web.Response(body=content, headers={
            "Content-Disposition": f'attachment; filename="{file_to_serve}"'
        })
    except FileNotFoundError:
        return web.Response(status=404, text="File not found")

async def start_server(file_to_serve: str):
    app = web.Application()
    app.router.add_get("/", lambda request: serve_file(request, file_to_serve))
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 1234)
    await site.start()
    logger.info("Server running on http://0.0.0.0:1234")

async def main(file_to_serve: str):
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # start server in background
    server_task = asyncio.create_task(start_server(file_to_serve))
    
    # wait a moment for server to start
    await asyncio.sleep(1)

    async with ModelTotal(URL) as client:
        # Scan an artifact
        try:
            result = await client.scan_artifact(
                model_id="model-id",
                model_name="my-model",
                model_version="1.0.0",
                model_url="http://host.docker.internal:1234/",
                org_id="org-456",
                model_metadata={"description": "Test model"}
            )
            logger.info(f"Scan completed. Result: {result}")
            json_result = json.dumps(json.loads(result.model_dump_json()), indent=4)
            open("output.json", "w").write(json_result)
        except Exception as e:
            logger.info(f"Scan failed: {e}")
    
if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))