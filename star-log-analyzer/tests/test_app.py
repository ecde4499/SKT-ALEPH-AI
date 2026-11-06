import io
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
    from app import app
except ModuleNotFoundError as exc:
    if exc.name != 'flask': raise
    app = None

@unittest.skipIf(app is None,'Flask not installed (offline local environment); tested in GitHub Actions/Render')
class FlaskTests(unittest.TestCase):
    def setUp(self):self.client=app.test_client()
    def test_home(self):
        r=self.client.get('/')
        self.assertEqual(r.status_code,200)
        self.assertIn('보안 로그를',r.get_data(as_text=True))
    def test_health(self):self.assertTrue(self.client.get('/health').get_json()['ok'])
    def test_sample_download(self):
        r=self.client.get('/sample.csv')
        self.assertEqual(r.status_code,200)
        self.assertIn(b'LOGIN_FAILURE',r.data)
    def test_sample_api(self):
        r=self.client.post('/api/analyze',data={'sample':'true'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.get_json()['total_alerts'],3)
    def test_upload_good(self):
        raw=b'timestamp,event_type,user,src_ip,bytes\n2026-11-06T08:00:00+09:00,LOGIN_SUCCESS,u,192.0.2.1,\n'
        r=self.client.post('/api/analyze',data={'file':(io.BytesIO(raw),'test.csv')})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.get_json()['total_alerts'],0)
    def test_upload_bad(self):
        r=self.client.post('/api/analyze',data={'file':(io.BytesIO(b'foo'),'test.csv')})
        self.assertEqual(r.status_code,400)
        self.assertIn('error',r.get_json())
    def test_no_file(self):
        r=self.client.post('/api/analyze')
        self.assertEqual(r.status_code,400)
    def test_size_limit(self):
        r=self.client.post('/api/analyze',data={'file':(io.BytesIO(b'A'*280000),'too_large.csv')})
        self.assertEqual(r.status_code,413)
    def test_no_store(self):
        self.assertNotIn('database',app.config)

if __name__=='__main__': unittest.main()
