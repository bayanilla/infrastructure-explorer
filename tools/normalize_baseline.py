"""Normalize only deliberate transport/metadata changes for behavior comparisons."""


def normalize(value):
    if isinstance(value, dict):
        return {
            k: normalize(v)
            for k, v in value.items()
            if k
            not in {
                "schema",
                "version",
                "job_id",
                "generated_utc",
                "resolution_generated_utc",
                "retrieved_at",
            }
            and not (k == "error" and value.get("name") == "RIPE RIS via RIPEstat")
        }
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        return value.replace("sourceapp=mucaro-infrastructure-explorer", "sourceapp=mucaro-pathfinder")
    return value
