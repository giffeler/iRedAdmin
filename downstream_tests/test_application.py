import runpy
import sys
from unittest.mock import patch

from conftest import settings, ROOT
from libs import iredutils, sqllib
from tools import ira_tool_lib


def test_postgres_factories_receive_no_mysql_socket():
    for name in ['vmail', 'iredadmin', 'amavisd', 'iredapd', 'fail2ban']:
        conn = iredutils.get_db_conn(name, 'postgres')
        assert 'unix_socket' not in conn.keywords
        with patch.object(ira_tool_lib, 'sql_dbn', 'postgres'):
            conn = ira_tool_lib.get_db_conn(name)
        assert 'unix_socket' not in conn.keywords
    wrapper = sqllib.PGSQLWrap()
    assert 'unix_socket' not in wrapper.conn.keywords
    wrapper.conn = None


def test_generic_invalid_socket_logs_error(caplog):
    settings.vmail_db_socket = 'relative.sock'
    assert iredutils.get_db_conn('vmail', 'mysql') is None
    assert 'vmail_db_socket' in caplog.text


def test_disclaimer_script_socket_export(live_database, tmp_path):
    conn = ira_tool_lib.get_db_conn('vmail')
    conn.query('CREATE TABLE IF NOT EXISTS domain (domain VARCHAR(255), disclaimer TEXT)')
    conn.query('CREATE TABLE IF NOT EXISTS alias_domain (alias_domain VARCHAR(255), target_domain VARCHAR(255))')
    conn.query('DELETE FROM domain')
    conn.query('DELETE FROM alias_domain')
    conn.insert('domain', domain='example.invalid', disclaimer='Socket export test')
    conn.insert('alias_domain', alias_domain='alias.invalid', target_domain='example.invalid')
    for suffix in ['host', 'server', 'port']:
        delattr(settings, 'vmail_db_' + suffix)
    with patch.object(sys, 'argv', ['dump_disclaimer.py', str(tmp_path)]):
        runpy.run_path(str(ROOT / 'tools/dump_disclaimer.py'), run_name='__main__')
    assert (tmp_path / 'example.invalid.txt').read_text() == '\n---------\nSocket export test\n'
    assert (tmp_path / 'alias.invalid.txt').read_text() == '\n---------\nSocket export test\n'
    conn.ctx.db.close()
