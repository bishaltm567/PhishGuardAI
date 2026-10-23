def status():
    """No external provider is enabled; never imply an unchecked indicator is clean."""
    return {"state": "not_checked", "providers": [], "message": "External lookups are disabled in this build."}
