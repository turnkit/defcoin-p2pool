import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path

from twisted.trial import unittest


class _Assets(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.scripts = {}
        self.styles = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and attrs.get('src'):
            self.scripts[attrs['src']] = attrs
        if tag == 'link' and attrs.get('rel') == 'stylesheet':
            self.styles[attrs.get('href')] = attrs


class TestFrontendSecurity(unittest.TestCase):
    def setUp(self):
        self.static = Path(__file__).resolve().parents[3] / 'frontend' / 'web-static'
        self.html = (self.static / 'index.html').read_text(encoding='utf-8')
        self.assets = _Assets()
        self.assets.feed(self.html)

    def test_external_dependencies_are_exact_and_have_sri(self):
        expected = {
            'https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/css/bootstrap.min.css':
                'sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css':
                'sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN',
            'https://code.jquery.com/jquery-3.7.1.min.js':
                'sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs',
            'https://cdn.jsdelivr.net/npm/bootstrap@3.4.1/dist/js/bootstrap.min.js':
                'sha384-aJ21OjlMXNL5UyIl/XNwTMqvzeRMZH2w8c5cRVpzpU8Y5bApTppSuUkhZXN0VxHd',
            'https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.30.1/moment.min.js':
                'sha384-KIix3a0qkeD2RPwPvpkJ+Knc91vkmDI+i2c7phIO+EfV3dpfDXIGSqQjpIaJXlR9',
        }
        all_assets = dict(self.assets.styles)
        all_assets.update(self.assets.scripts)
        for url, integrity in expected.items():
            self.assertIn(url, all_assets)
            self.assertEqual(all_assets[url].get('integrity'), integrity)
            self.assertEqual(all_assets[url].get('crossorigin'), 'anonymous')

    def test_local_third_party_sri_matches_file(self):
        for src in ('js/jquery-dateFormat.min.js',
                    'js/bootstrap-sortable.js', 'js/highcharts.js'):
            attrs = self.assets.scripts[src]
            digest = base64.b64encode(hashlib.sha384(
                (self.static / src).read_bytes()).digest()).decode('ascii')
            self.assertEqual(attrs.get('integrity'), 'sha384-' + digest)

    def test_live_html_corruption_is_absent(self):
        self.assertNotIn('aria-hidden "true"', self.html)
        self.assertNotIn('</script>>', self.html)
        self.assertIn('aria-hidden="true"', self.html)

    def test_share_age_and_twenty_year_controls_remain(self):
        self.assertIn('Share Age', self.html)
        self.assertIn('id="twenty_years"', self.html)

    def test_optional_header_is_default_off_and_same_origin_guarded(self):
        config = (self.static / 'js' / 'config.js').read_text(encoding='utf-8')
        frontend = (self.static / 'js' / 'p2pool.js').read_text(encoding='utf-8')
        self.assertIn('header_content_url: ""', config)
        self.assertIn(
            'headerContentUrl.origin === window.location.origin', frontend)
