#!/usr/bin/env python3
"""Offline parser/refusal checks; JS tests use synthetic services only."""

import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('contract', Path(__file__).with_name('probe-copilot-auth-contract.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ContractTests(unittest.TestCase):
    def test_truncated_macho_is_sanitized(self):
        for data in (b'\xcf\xfa\xed\xfe', b'\xcf\xfa\xed\xfe' + bytes(12) + struct.pack('<I', 1) + bytes(12)):
            with self.subTest(length=len(data)), patch.object(probe, 'regular_bytes', return_value=data):
                with self.assertRaisesRegex(ValueError, 'malformed public SEA archive'):
                    probe.standalone_files(Path('synthetic'))

    def test_public_sea_members_roundtrip(self):
        archive_bytes = io.BytesIO()
        with probe.tarfile.open(fileobj=archive_bytes, mode='w:gz') as archive:
            for name in ('package.json', 'schemas/api.schema.json', 'prebuilds/darwin-arm64/runtime.node'):
                member = probe.tarfile.TarInfo('package/' + name)
                member.size = 3
                archive.addfile(member, io.BytesIO(b'abc'))
        field = lambda value: struct.pack('<Q', len(value)) + value
        blob = bytes(9) + field(b'sea-loader.js') + field(b'loader') + struct.pack('<Q', 1) + field(b'copilot.tgz') + field(archive_bytes.getvalue())
        header = struct.pack('<8I', 0xfeedfacf, 0, 0, 0, 1, 56, 0, 0)
        segment = struct.pack('<II16sQQQQ', 25, 56, b'NODE_SEA', 0, 0, 88, len(blob))
        with patch.object(probe, 'regular_bytes', return_value=header + segment + blob):
            self.assertEqual(set(probe.standalone_files(Path('synthetic')).values()), {b'abc'})

    def test_hash_refusal_precedes_execution(self):
        with patch.object(probe.platform, 'system', return_value='Darwin'), \
                patch.object(probe, 'regular_bytes', side_effect=[json.dumps({'version':'1.0.95'}).encode(), b'unreviewed']), \
                patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'unreviewed native artifact'):
                probe.isolated_native(Path('/synthetic'), Path('/node'))
            spawn.assert_not_called()

    def test_expanding_unrelated_tar_refused_before_parsing(self):
        payload = io.BytesIO()
        with probe.tarfile.open(fileobj=payload, mode='w:gz') as archive:
            member = probe.tarfile.TarInfo('unrelated-large-file')
            member.size = 65536
            archive.addfile(member, io.BytesIO(bytes(member.size)))
        compressed = payload.getvalue()
        self.assertLess(len(compressed), 1024)
        field = lambda value: struct.pack('<Q', len(value)) + value
        blob = bytes(9) + field(b'sea-loader.js') + field(b'loader') + struct.pack('<Q', 1) + field(b'copilot.tgz') + field(compressed)
        header = struct.pack('<8I', 0xfeedfacf, 0, 0, 0, 1, 56, 0, 0)
        segment = struct.pack('<II16sQQQQ', 25, 56, b'NODE_SEA', 0, 0, 88, len(blob))
        with patch.object(probe, 'TAR_LIMIT', 1024), \
                patch.object(probe, 'regular_bytes', return_value=header + segment + blob), \
                patch.object(probe.tarfile, 'open') as parse, patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'decompressed limit'):
                probe.standalone_files(Path('synthetic'))
            parse.assert_not_called()
            spawn.assert_not_called()

    def test_invalid_deflate_is_sanitized_before_execution(self):
        compressed = bytes.fromhex('1f8b0800000000000003') + b'\x07' + bytes(8)
        with self.assertRaises(probe.zlib.error):
            probe.gzip.decompress(compressed)
        field = lambda value: struct.pack('<Q', len(value)) + value
        blob = bytes(9) + field(b'sea-loader.js') + field(b'loader') + struct.pack('<Q', 1) + field(b'copilot.tgz') + field(compressed)
        header = struct.pack('<8I', 0xfeedfacf, 0, 0, 0, 1, 56, 0, 0)
        segment = struct.pack('<II16sQQQQ', 25, 56, b'NODE_SEA', 0, 0, 88, len(blob))
        with patch.object(probe, 'regular_bytes', return_value=header + segment + blob), \
                patch.object(probe.tarfile, 'open') as parse, patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(ValueError, 'malformed public SEA archive'):
                probe.standalone_files(Path('synthetic'))
            parse.assert_not_called()
            spawn.assert_not_called()

    def test_old_session_version_refuses_before_addon_read(self):
        with patch.object(probe.platform, 'system', return_value='Darwin'), \
                patch.object(probe, 'regular_bytes', return_value=b'{"version":"1.0.94-5"}') as read:
            with self.assertRaisesRegex(ValueError, 'schema-only'):
                probe.isolated_native(Path('/synthetic'), Path('/node'))
            self.assertEqual(read.call_count, 1)

    def test_session_failures_never_report_success(self):
        self.assertIsNotNone(shutil.which('node'), 'Node is required for synthetic JS regression checks')
        source = "const assert=require('node:assert/strict');\n" + probe.SESSION_GATES + r'''
const scenario=process.argv[2];
let reads=0,current=0,applied=0;
const server={invokeMethod:async()=>{reads++;return JSON.stringify({ok:true,result:
  reads===3?{kind:'status',status:{isAuthenticated:false}}:{kind:'activeAccount',account:null}});}};
const handle={current:async()=>{current++;if(scenario==='current')throw Error('unexpected');return null;},
currentAndApplyToSession:async()=>{applied++;if(scenario==='applied')throw Error('unexpected');return null;}};
checkSession(server,handle,'synthetic',scenario!=='init').then(()=>{
  assert.equal(current,1);assert.equal(applied,1);console.log('PASS');
}).catch(()=>{console.log(`FAIL reads=${reads} current=${current} applied=${applied}`);process.exitCode=1;});
'''
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / 'checks.cjs'
            script.write_text(source)
            for scenario, expected in [('ok','PASS'), ('init','FAIL reads=0 current=0 applied=0'),
                                       ('current','FAIL reads=1 current=1 applied=0'),
                                       ('applied','FAIL reads=1 current=1 applied=1')]:
                with self.subTest(scenario=scenario):
                    result = subprocess.run([shutil.which('node'), str(script), scenario],
                                            capture_output=True, text=True, timeout=10,
                                            env={'PATH':'/usr/bin:/bin'}, cwd=temporary)
                    self.assertEqual(result.returncode, int(scenario != 'ok'))
                    self.assertEqual(result.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()
