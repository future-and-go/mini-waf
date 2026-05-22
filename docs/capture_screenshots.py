#!/usr/bin/env python3
"""Capture screenshots from PRX-WAF admin panel for documentation."""
import os, time
from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost:16827/ui"
USERNAME = "admin"
PASSWORD = "6J8rIlw2wDPAD35LRuPlgL0v"
OUT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(OUT_DIR, exist_ok=True)

PAGES = [
    ("dashboard",        "/"),
    ("hosts",            "/hosts"),
    ("ip_rules",         "/ip-rules"),
    ("url_rules",        "/url-rules"),
    ("security_events",  "/security-events"),
    ("security_logs",    "/security-logs"),
    ("ssl_certificates", "/ssl"),
    ("cc_protection",    "/cc-protection"),
    ("notifications",    "/notifications"),
    ("settings",         "/settings"),
    ("rule_manager",     "/rules"),
    ("custom_rules",     "/custom-rules"),
    ("rule_sources",     "/rule-sources"),
    ("rule_analytics",   "/rule-analytics"),
    ("bot_detection",    "/bot-detection"),
    ("cluster_overview", "/cluster"),
    ("cluster_tokens",   "/cluster/tokens"),
]

def save(page, name):
    path = os.path.join(OUT_DIR, f"{name}.png")
    page.screenshot(path=path, full_page=False)
    print(f"  saved: {name}.png")

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        print("Login...")
        page.goto(f"{BASE_URL}/login", wait_until="networkidle", timeout=15000)
        time.sleep(1)
        save(page, "00_login")

        # Try multiple selector strategies for login form
        try:
            page.locator('input').first.fill(USERNAME)
            page.locator('input[type="password"]').fill(PASSWORD)
            page.locator('button[type="submit"]').click()
        except Exception:
            page.fill('input:first-of-type', USERNAME)
            page.fill('input[type="password"]', PASSWORD)
            page.click('button[type="submit"]')

        page.wait_for_load_state("networkidle", timeout=15000)
        time.sleep(2)
        save(page, "01_dashboard_after_login")

        for slug, path in PAGES:
            try:
                print(f"  {slug}...")
                page.goto(f"{BASE_URL}{path}", wait_until="networkidle", timeout=15000)
                time.sleep(1.5)
                save(page, f"page_{slug}")
            except Exception as e:
                print(f"    WARN: {slug}: {e}")

        # Dashboard scrolled
        try:
            page.goto(f"{BASE_URL}/", wait_until="networkidle")
            time.sleep(1)
            page.evaluate("window.scrollTo(0,400)")
            time.sleep(0.8)
            save(page, "page_dashboard_chart")
            page.evaluate("window.scrollTo(0,900)")
            time.sleep(0.8)
            save(page, "page_dashboard_stats")
        except Exception as e:
            print(f"  WARN dashboard scroll: {e}")

        browser.close()
    print(f"Done. Screenshots in: {OUT_DIR}")

if __name__ == "__main__":
    run()
