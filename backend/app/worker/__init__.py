"""
Worker package for distributed scan processing.

Provides standalone worker capability for multi-node deployments.
In embedded mode (default), the worker runs as an asyncio task
inside the main FastAPI process.
"""
