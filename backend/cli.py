import asyncio
import sys
from services.orchestrator_pro import run

async def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <target>")
        return
    target = sys.argv[1]
    result = await run(target)
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
