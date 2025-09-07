import time

from Core.engine import Engine
from Lib.log import logger


def main():
    try:
        engine = Engine()
        engine.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Program interrupted by user")
    except Exception as e:
        logger.error(f"Program error occurred: {e}")
    finally:
        if 'engine' in locals() and engine:
            engine.stop()
        logger.info("Program has been closed")


if __name__ == '__main__':
    main()
