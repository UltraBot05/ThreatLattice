"""Database connections for the ETL scripts.

Contract (HANDOFF 10.5):
- get_mysql() returns a PyMySQL DB-API connection with autocommit OFF, so each
  loader decides where its transaction starts and ends (commit / rollback).
- Loaders only use %s placeholders, never string formatting of values.
"""
from __future__ import annotations

import pymysql
from neo4j import Driver, GraphDatabase

from etl.common import config


def get_mysql() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DATABASE,
        charset="utf8mb4",
        autocommit=False,
        local_infile=False,
    )


def get_neo4j() -> Driver:
    """Caller closes it (use as a context manager: `with get_neo4j() as drv:`)."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    driver.verify_connectivity()
    return driver
