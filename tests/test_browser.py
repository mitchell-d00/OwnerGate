"""Chromium journey over a real Uvicorn socket, desktop and mobile."""
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from conftest import TOKEN


def test_browser_owner_journey(pilot):
    _,client,current,_=pilot
    current[0]=None
    evidence=Path(os.environ.get('OWNERGATE_SCREENSHOTS','/tmp/ownergate-screenshots'))
    evidence.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as p:
        executable=os.environ.get('CHROMIUM_EXECUTABLE','/usr/bin/chromium')
        browser=p.chromium.launch(executable_path=executable if Path(executable).exists() else None,args=['--no-sandbox'])
        context=browser.new_context(viewport={'width':1440,'height':1000})
        page=context.new_page()
        errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(str(client.base_url))
        expect(page.locator('#login')).to_be_visible()
        page.locator('#token').fill('wrong-secret-that-is-longer-than-thirty-two')
        page.get_by_role('button',name='Open workspace').click()
        expect(page.locator('#message')).to_contain_text('admin_authentication_required')
        page.locator('#token').fill(TOKEN)
        page.get_by_role('button',name='Open workspace').click()
        expect(page.locator('#app')).to_be_visible()
        page.locator('[data-view="lab"]').click()
        checks=page.get_by_role('button',name='Run HTTP check')
        assert checks.count()==8
        for index in range(8):
            checks.nth(index).click()
            expect(page.locator('#message')).to_contain_text('PASS',timeout=20000)
        page.locator('[data-view="overview"]').click()
        expect(page.locator('.stat strong').nth(0)).to_have_text('9')
        expect(page.locator('.stat strong').nth(1)).to_have_text('2')
        expect(page.locator('.stat strong').nth(2)).to_have_text('7')
        page.screenshot(path=str(evidence/'overview-desktop.png'),full_page=True)
        page.locator('[data-view="machines"]').click()
        expect(page.get_by_text('Registered machine participants',exact=True)).to_be_visible()
        page.locator('[data-view="policies"]').click()
        expect(page.get_by_text('Protect a real endpoint',exact=True)).to_be_visible()
        editors=page.locator('textarea')
        editors.nth(0).fill('{')
        page.get_by_role('button',name='Validate & save').nth(0).click()
        expect(page.locator('#message')).not_to_be_empty()
        page.locator('[data-view="traffic"]').click()
        page.get_by_label('Decision',exact=True).fill('deny')
        assert page.locator('tbody tr').count()==7
        page.locator('[data-view="audit"]').click()
        page.get_by_role('button',name='Check integrity').click()
        expect(page.locator('#message')).to_contain_text('"valid": true')
        with page.expect_download() as dl:
            page.get_by_role('button',name='Export signed evidence').click()
        assert dl.value.suggested_filename=='ownergate-audit.json'
        page.set_viewport_size({'width':390,'height':844})
        page.locator('[data-view="overview"]').click()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(evidence/'overview-mobile.png'),full_page=True)
        page.reload()
        expect(page.locator('#login')).to_be_visible()
        assert page.evaluate('localStorage.length')==0
        assert not errors,errors
        browser.close()
