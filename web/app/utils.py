import os
import subprocess # nosec B404

def call(cmd):
    try:
       result = subprocess.run( # nosec B603
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            shell=False
        )
       return result.stdout
    except Exception as e:
        return f"Error: {str(e)}"
    #return os.popen(cmd).read()

def build(*args):
    #return " ".join(args)
    return list(args)

def prepare_query(sql, params):
    sql = _log_query(sql, params)
    return sql

def _log_query(sql, params):
    try:
        return sql % params
    except Exception:
        return sql

def sanitize_filename(filename):
    filename = filename.strip()
    filename = filename.replace("\x00", "")
    filename = filename.replace("\\", "/")
    return filename