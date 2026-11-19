"""
Queue abstraction layer for distributed scan processing.

Provides pluggable backends (memory, Redis) for scan task queuing
with a common interface. Default is memory backend for single-process
deployments; Redis backend enables multi-node distributed workers.
"""
