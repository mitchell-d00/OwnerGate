"""Test the actual buildless Pages artifact under the /OwnerGate/ URL prefix."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import threading
from playwright.sync_api import sync_playwright, expect


def test_pages_demo(tmp_path):
    root=Path(__file__).resolve().parents[1]
    artifact=tmp_path/'OwnerGate'
    artifact.mkdir()
    shutil.copy(root/'index.html',artifact/'index.html')
    shutil.copytree(root/'site',artifact/'site')
    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),partial(Quiet,directory=tmp_path))
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    base=f'http://127.0.0.1:{server.server_port}/OwnerGate/'
    screenshots=Path(os.environ.get('OWNERGATE_SCREENSHOTS','/tmp/ownergate-pages'))
    screenshots.mkdir(parents=True,exist_ok=True)
    try:
        with sync_playwright() as p:
            executable=os.environ.get('CHROMIUM_EXECUTABLE','/usr/bin/chromium')
            browser=p.chromium.launch(executable_path=executable if Path(executable).exists() else None,args=['--no-sandbox'])
            page=browser.new_page(viewport={'width':1440,'height':1000})
            errors=[];requests=[]
            page.on('pageerror',lambda e:errors.append(str(e)))
            page.on('request',lambda r:requests.append(r.url))
            page.goto(base)
            expect(page.locator('.stats')).to_be_visible()
            expect(page.locator('.stat strong').nth(0)).to_have_text('3')
            expect(page.locator('.demo-banner')).to_contain_text('not HTTP enforcement')
            assert page.get_by_label('Administrator token').count()==0
            page.screenshot(path=str(screenshots/'pages-desktop.png'),full_page=True)
            page.get_by_role('button',name='Try an authorized machine').click()
            expect(page.locator('#message')).to_contain_text('SIMULATED · ALLOW')
            page.get_by_role('button',name='Try an unknown machine').click()
            expect(page.locator('#message')).to_contain_text('SIMULATED · DENY')
            page.locator('[data-view="policies"]').click()
            page.get_by_label('Explicitly deny all machines').check()
            page.get_by_role('button',name='Save demo policy').click()
            expect(page.locator('#message')).to_contain_text('saved')
            page.get_by_role('button',name='Try read',exact=True).click()
            expect(page.locator('#message')).to_contain_text('deny rule')
            page.locator('[data-view="lab"]').click()
            for i in range(8):
                page.get_by_role('button',name='Run demo check').nth(i).click()
                expect(page.locator('#message')).to_contain_text('PASS · SIMULATED')
            page.locator('[data-view="machines"]').click()
            row=page.locator('tbody tr').filter(has_text='research-agent')
            row.get_by_role('button',name='Revoke',exact=True).click()
            expect(page.locator('#message')).to_contain_text('revoked')
            page.locator('tbody tr').filter(has_text='research-agent').get_by_role('button',name='Request read').click()
            expect(page.locator('#message')).to_contain_text('permanently revoked')
            page.locator('[data-view="traffic"]').click()
            page.get_by_label('Decision',exact=True).fill('allow')
            assert page.locator('tbody tr').count()>=2
            assert page.locator('tbody .pill.deny').count()==0
            page.locator('[data-view="audit"]').click()
            page.get_by_role('button',name='Verify demo integrity').click()
            expect(page.locator('#message')).to_contain_text('"valid": true')
            page.get_by_role('button',name='Test a tampered record').click()
            expect(page.locator('#message')).to_contain_text('TAMPERING DETECTED')
            with page.expect_download() as download:
                page.get_by_role('button',name='Export demo evidence').click()
            data=json.loads(Path(download.value.path()).read_text())
            assert data['kind']=='BROWSER_DEMONSTRATION_ONLY'
            assert all('PRIVATE' not in str(v) for v in data.values())
            page.locator('[data-view="guide"]').click()
            expect(page.get_by_text('01 / Start OwnerGate locally')).to_be_visible()
            assert page.get_by_text('ownergate serve',exact=False).count()>0
            page.set_viewport_size({'width':390,'height':844})
            page.locator('[data-view="overview"]').click()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(screenshots/'pages-mobile.png'),full_page=True)
            page.get_by_role('button',name='Reset demo').click()
            expect(page.locator('#message')).to_contain_text('Demo reset')
            expect(page.locator('.stat strong').nth(0)).to_have_text('3')
            page.reload()
            expect(page.locator('.stats')).to_be_visible()
            assert page.evaluate('localStorage.length')==0
            assert not errors,errors
            assert all(url.startswith(base) for url in requests),requests
            assert not any('/api/' in url for url in requests)
            browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(3)
