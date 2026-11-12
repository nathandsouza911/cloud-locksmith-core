class ManualReviewRequiredExecutor:
    async def execute(self, graph_client, evidence: dict) -> dict:
        raise RuntimeError("This control is advisory only and requires manual review.")

    async def rollback(self, graph_client, snapshot: dict) -> None:
        return None
