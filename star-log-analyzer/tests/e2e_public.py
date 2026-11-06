"""Browser E2E against real public Render URL, running in GitHub Actions.

Environment:
  LOGSCOPE_BASE_URL=https://logscope-star-ecde4499.onrender.com/
  CHROME_BIN=/usr/bin/google-chrome (optional)
No account or production personal data is used.
"""
from __future__ import annotations

import csv
import io
import os
from pathlib import Path
import shutil
from playwright.sync_api import sync_playwright

BASE = os.environ.get('LOGSCOPE_BASE_URL', 'https://logscope-star-ecde4499.onrender.com/').rstrip('/') + '/'
CHROME = os.environ.get('CHROME_BIN') or shutil.which('google-chrome') or shutil.which('chromium')
EVIDENCE = Path(os.environ.get('BROWSER_EVIDENCE_DIR', '/tmp/logscope-browser-evidence'))
EVIDENCE.mkdir(parents=True, exist_ok=True)


def expect(condition, description):
    if not condition:
        raise AssertionError(description)
    print('PASS:', description)


def main():
    with sync_playwright() as p:
        kwargs = {'headless': True, 'args': ['--no-sandbox', '--disable-dev-shm-usage']}
        if CHROME:
            kwargs['executable_path'] = CHROME
        browser = p.chromium.launch(**kwargs)
        context = browser.new_context(accept_downloads=True, viewport={'width': 1365, 'height': 900}, locale='ko-KR')
        page = context.new_page()
        errors = []
        page.on('pageerror', lambda err: errors.append(str(err)))
        response = page.goto(BASE, wait_until='domcontentloaded', timeout=70000)
        expect(response is not None and response.status == 200, 'P01 anonymous public home 200')
        expect('보안 로그를' in page.locator('h1').inner_text(), 'P02 purpose visible without login')
        expect(page.locator('#downloadBtn').is_disabled(), 'P03 export initially disabled')
        page.locator('#analyzeBtn').click()
        page.locator('#metricAlerts').get_by_text('3').wait_for(timeout=20000)
        expect(page.locator('#metricTotal').inner_text() == '11', 'P04 sample 11 events')
        expect(page.locator('#metricAlerts').inner_text() == '3', 'P05 sample 3 alerts')
        expect(page.locator('#metricHigh').inner_text() == '1' and page.locator('#metricMedium').inner_text() == '2', 'P06 severities high 1 medium 2')
        expect(page.locator('#alertsBody tr').count() == 3, 'P07 three incident rows shown')
        expect(page.locator('#downloadBtn').is_enabled(), 'P08 export enabled after valid result')

        with page.expect_download(timeout=20000) as d:
            page.locator('#downloadBtn').click()
        download = d.value
        path = EVIDENCE / 'report-desktop.csv'
        download.save_as(path)
        with path.open(encoding='utf-8-sig', newline='') as f:
            report = list(csv.DictReader(f))
        expect(len(report) == 3, 'P09 real browser CSV download contains 3 alerts')
        expect({r['code'] for r in report} == {'BRUTE_FORCE', 'OFFHOUR_LOGIN', 'TRAFFIC_SPIKE'}, 'P10 exported rule codes match table')
        for tr, r in zip(page.locator('#alertsBody tr').all(), report):
            cells = tr.locator('td')
            expect(r['code'] in cells.nth(1).inner_text() and r['evidence'] in cells.nth(4).inner_text(), 'P11 exported row matches visible detection')

        sample_resp = context.request.get(BASE + 'sample.csv', timeout=20000)
        expect(sample_resp.status == 200, 'P12 sample CSV downloadable anonymously')
        sample_bytes = sample_resp.body()
        page.locator('#uploadBtn').click()
        expect(page.locator('#downloadBtn').is_disabled() and page.locator('#metricAlerts').inner_text() == '—', 'P13 switching input resets stale previous result')
        page.locator('#fileInput').set_input_files({'name':'sample.csv','mimeType':'text/csv','buffer':sample_bytes})
        page.locator('#analyzeBtn').click()
        page.locator('#metricAlerts').get_by_text('3').wait_for(timeout=20000)
        expect(page.locator('#metricTotal').inner_text() == '11', 'P14 real upload of downloaded sample reproduces 11 events, 3 alerts')

        malformed = b'timestamp,event_type,user,src_ip,bytes\nWRONG,LOGIN_SUCCESS,test,192.0.2.1,\n'
        page.locator('#fileInput').set_input_files({'name':'invalid.csv','mimeType':'text/csv','buffer':malformed})
        expect(page.locator('#downloadBtn').is_disabled(), 'P15 changing file resets download before new result')
        page.locator('#analyzeBtn').click()
        page.locator('#errorBox').wait_for(state='visible', timeout=20000)
        expect('날짜' in page.locator('#errorBox').inner_text(), 'P16 malformed CSV shows user-facing error')
        expect(page.locator('#downloadBtn').is_disabled() and page.locator('#metricAlerts').inner_text() == '—', 'P17 invalid upload leaves no stale result')
        page.screenshot(path=str(EVIDENCE / 'desktop-error.png'), full_page=True)

        page.locator('#fileInput').set_input_files({'name':'sample.csv','mimeType':'text/csv','buffer':sample_bytes})
        page.locator('#analyzeBtn').click()
        page.locator('#metricAlerts').get_by_text('3').wait_for(timeout=20000)
        expect(page.locator('#errorBox').is_hidden(), 'P18 valid retry recovers from error')
        expect(not errors, 'P19 no uncaught JS exceptions')
        page.screenshot(path=str(EVIDENCE / 'desktop-results.png'), full_page=True)

        mobile = browser.new_context(accept_downloads=True, viewport={'width':390,'height':844}, is_mobile=True, device_scale_factor=2, has_touch=True)
        mp = mobile.new_page()
        response = mp.goto(BASE, wait_until='domcontentloaded', timeout=70000)
        expect(response is not None and response.status == 200, 'P20 mobile anonymous home')
        mp.locator('#analyzeBtn').click()
        mp.locator('#metricAlerts').get_by_text('3').wait_for(timeout=20000)
        expect(mp.locator('#metricAlerts').inner_text() == '3', 'P21 mobile sample analysis works')
        width = mp.evaluate('({scroll: document.documentElement.scrollWidth, viewport: window.innerWidth})')
        expect(width['scroll'] <= width['viewport']+2, 'P22 mobile page has no horizontal overflow')
        mp.screenshot(path=str(EVIDENCE / 'mobile-results.png'), full_page=True)
        # Regression: a slow response must not replace the screen after input changes.
        page.evaluate("""() => {
          const actualFetch = window.fetch.bind(window);
          window.__releaseHeldAnalysis = null;
          window.fetch = (...args) => {
            if (String(args[0]).includes('/api/analyze') && window.__holdAnalysis) {
              window.__holdAnalysis = false;
              return new Promise((resolve, reject) => {
                window.__releaseHeldAnalysis = () => actualFetch(...args).then(resolve, reject);
              });
            }
            return actualFetch(...args);
          };
          window.__holdAnalysis = true;
        }""")
        page.locator('#sampleBtn').click()
        page.locator('#analyzeBtn').click()
        page.wait_for_function('typeof window.__releaseHeldAnalysis === "function"')
        page.locator('#uploadBtn').click()
        expect(page.locator('#metricAlerts').inner_text() == '—', 'P23 switching while pending clears results')
        page.evaluate('window.__releaseHeldAnalysis()')
        page.wait_for_function('!document.querySelector("#analyzeBtn").disabled')
        expect(page.locator('#metricAlerts').inner_text() == '—' and page.locator('#downloadBtn').is_disabled(),
               'P24 late analysis response cannot overwrite changed input')
        print('BROWSER_RESULT: 24 checks PASS (plus 3 row matches)')
        browser.close()

if __name__ == '__main__':
    main()
