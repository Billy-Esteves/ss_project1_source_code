
"""
Utility helper functions.

This module provides helper functions for query preparation,
filename sanitization, and optional query logging utilities.
"""

import os

# temp
import logging

#def call(cmd):
#    return os.popen(cmd).read()

#def build(*args):
#    return " ".join(args)

def prepare_query(sql, params):
    """
    Prepare a SQL query and its parameters.

    Args:
        sql (str):
            SQL query string.
        params (tuple):
            Parameters associated with the query.

    Returns:
        tuple:
            A tuple containing the SQL query and parameters.
    """
    return sql, params

def _log_query(sql, params):
    """
    Log a formatted SQL query for debugging purposes.

    Args:
        sql (str):
            SQL query string.
        params (tuple):
            Query parameters.

    Returns:
        None
    """
    try:
        logging.debug(sql % params)
    except Exception as e:
        logging.warning("Unexpected error while logging query: %s", e)

def sanitize_filename(filename):
    """
    Sanitize a filename string.

    Removes null bytes and normalizes path separators.

    Args:
        filename (str):
            Filename to sanitize.

    Returns:
        str:
            Sanitized filename.
    """
    filename = filename.strip()
    filename = filename.replace("\x00", "")
    filename = filename.replace("\\", "/")
    return filename
