from prefect import flow, get_run_logger, task


@task(retries=2, retry_delay_seconds=10)
def hello_task() -> None:
    logger = get_run_logger()
    logger.info("Phase 3 hello task started")


@flow(name="p3-hello-flow")
def hello_flow(run_date: str = "2026-02-22") -> None:
    logger = get_run_logger()
    logger.info("Running hello flow for run_date=%s", run_date)
    hello_task()
    logger.info("Hello flow completed")


if __name__ == "__main__":
    hello_flow()
