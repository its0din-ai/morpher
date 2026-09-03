#!/usr/bin/env python3
"""
Morpher - Cloudflare Workers forwarding proxies with out-of-band visit logging.

Morpher is an evolution of FlareProx. It deploys Cloudflare Workers that
forward traffic for any target URL and adds:

  1. Out-of-band visit logging - when a proxied request is heading to one of
     the configured target domains, a log entry (real connecting IP, the
     masked X-Forwarded-For the origin saw, method, target, status, time) is
     buffered inside the Worker and POSTed in batches to your own listener
     (webhook). No KV or hosting is needed on Cloudflare's side.

  2. X-Morph-Real-Ip header - the real IP "in front of" the proxy (the peer
     Cloudflare saw connect, i.e. CF-Connecting-IP) is forwarded to the
     target/origin in a custom header.
"""

import argparse
import getpass
import json
import os
import random
import re
import requests
import string
import sys
import time
from typing import Dict, List, Optional

WORKER_PREFIX = "morpher-"
CONFIG_FILE = "morpher.json"
STATE_FILE = "morpher_state.json"
ENDPOINTS_FILE = "morpher_endpoints.json"
MAX_WORKER_NAME = 60


def normalize_worker_name(raw: Optional[str]) -> str:
    """Turn a user-supplied worker name into a valid, morpher-managed name.

    Keeps only [a-z0-9_-], lowercases it, and guarantees the reserved
    'morpher-' prefix so list/update/cleanup keep working.
    """
    name = (raw or "").strip()
    if not name:
        raise MorpherError("Worker name cannot be empty")
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-").lower()
    if not name:
        raise MorpherError(
            f"Invalid worker name '{raw}' - use only letters, numbers, '-' or '_'"
        )
    if len(name) > MAX_WORKER_NAME:
        raise MorpherError(
            f"Worker name '{raw}' is too long (max {MAX_WORKER_NAME} chars)"
        )
    if not name.startswith(WORKER_PREFIX):
        name = WORKER_PREFIX + name
    return name


class MorpherError(Exception):
    """Custom exception for Morpher-specific errors."""
    pass


class CloudflareManager:
    """Manages Cloudflare Worker deployments for Morpher."""

    def __init__(self, api_token: str, account_id: str, zone_id: Optional[str] = None):
        self.api_token = api_token
        self.account_id = account_id
        self.zone_id = zone_id
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        self._account_subdomain = None

    # --------------------------------------------------------- shared helpers

    def _generate_subdomain_name(self) -> str:
        """Generate a subdomain name for new accounts."""
        account_prefix = self.account_id[:10].lower()
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
        return f"{account_prefix}-{random_suffix}"

    def ensure_subdomain_provisioned(self) -> str:
        """Provision a workers.dev subdomain for the account if it doesn't exist."""
        url = f"{self.base_url}/accounts/{self.account_id}/workers/subdomain"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                subdomain = data.get("result", {}).get("subdomain")
                if subdomain:
                    return subdomain
        except requests.RequestException:
            pass

        subdomain_name = self._generate_subdomain_name()
        try:
            response = requests.put(
                url, headers=self.headers, json={"subdomain": subdomain_name}, timeout=30
            )
        except requests.RequestException as e:
            raise MorpherError(f"Network error while provisioning subdomain: {e}")

        if response.status_code == 200:
            data = response.json()
            subdomain = data.get("result", {}).get("subdomain")
            if subdomain:
                print(f"\n  ✓ Subdomain provisioned: {subdomain}.workers.dev\n")
                return subdomain
        elif response.status_code == 409:
            try:
                data = requests.get(url, headers=self.headers, timeout=30).json()
                subdomain = data.get("result", {}).get("subdomain")
                if subdomain:
                    return subdomain
            except (requests.RequestException, ValueError):
                pass
            raise MorpherError(
                "Subdomain already exists but couldn't retrieve it. "
                "Please visit https://dash.cloudflare.com -> Workers & Pages"
            )

        error_data = response.json() if response.content else {}
        errors = error_data.get("errors") or []
        msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
        raise MorpherError(
            f"Failed to provision workers.dev subdomain (HTTP {response.status_code}): {msg}. "
            "Ensure your API token has 'Workers Scripts:Write' permission."
        )

    @property
    def worker_subdomain(self) -> str:
        """Get the workers.dev subdomain for the account (auto-provisions on 404)."""
        if self._account_subdomain:
            return self._account_subdomain

        url = f"{self.base_url}/accounts/{self.account_id}/workers/subdomain"
        max_retries = 3

        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=self.headers, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    subdomain = data.get("result", {}).get("subdomain")
                    if subdomain:
                        self._account_subdomain = subdomain
                        return subdomain
                    if attempt < max_retries - 1:
                        time.sleep(1)
                        continue
                    raise MorpherError(
                        "Cloudflare API returned no workers.dev subdomain. "
                        "Please check https://dash.cloudflare.com -> Workers & Pages"
                    )
                elif response.status_code == 404:
                    if attempt == 0:
                        print("\n  ⚙ Setting up workers.dev subdomain for your account...")
                        try:
                            subdomain = self.ensure_subdomain_provisioned()
                            if subdomain:
                                self._account_subdomain = subdomain
                                return subdomain
                        except MorpherError:
                            if attempt < max_retries - 1:
                                time.sleep(2)
                                continue
                            raise
                    else:
                        if attempt < max_retries - 1:
                            time.sleep(2)
                            continue
                        raise MorpherError(
                            "Workers subdomain could not be provisioned automatically. "
                            "Please visit https://dash.cloudflare.com -> Workers & Pages "
                            "to initialize your account."
                        )
                else:
                    raise MorpherError(
                        f"Failed to retrieve workers.dev subdomain (HTTP {response.status_code}). "
                        "Please check your API token has 'Workers Scripts:Read' permission."
                    )
            except requests.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                raise MorpherError(f"Network error while retrieving workers.dev subdomain: {e}")

        raise MorpherError("Failed to retrieve workers.dev subdomain after retries")

    # --------------------------------------------------------- worker deploy

    @staticmethod
    def read_worker_script() -> str:
        """Read the Worker script that ships next to this file."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker.js")
        if not os.path.exists(path):
            raise MorpherError(f"worker.js not found next to morpher.py ({path})")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def _generate_worker_name(self) -> str:
        timestamp = str(int(time.time()))
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        return f"{WORKER_PREFIX}{timestamp}-{random_suffix}"

    @staticmethod
    def _oob_bindings(oob: Dict) -> List[Dict]:
        """
        Build the Worker bindings that configure out-of-band logging.
        Empty/absent values simply leave the binding out (logging disabled).
        OOB_AUTH is only bound alongside OOB_URL so an open (auth:none)
        listener never receives an Authorization header.
        """
        bindings = []
        if oob.get("url"):
            bindings.append({"type": "secret_text", "name": "OOB_URL", "text": oob["url"]})
            bindings.append({
                "type": "plain_text",
                "name": "OOB_AUTH",
                "text": "none" if oob.get("auth") == "none" else "bearer",
            })
            if oob.get("auth") != "none" and oob.get("token"):
                bindings.append({"type": "secret_text", "name": "OOB_TOKEN", "text": oob["token"]})
            if oob.get("domains"):
                bindings.append({
                    "type": "plain_text",
                    "name": "OOB_DOMAINS",
                    "text": ",".join(oob["domains"]),
                })
        return bindings

    @staticmethod
    def _cf_error(response: requests.Response) -> str:
        """Best-effort extraction of the first Cloudflare API error message."""
        try:
            data = response.json()
        except (ValueError, AttributeError):
            data = {}
        errors = data.get("errors") or []
        if errors:
            msgs = []
            for e in errors:
                code = e.get("code")
                message = e.get("message", "")
                msgs.append(f"[{code}] {message}" if code else message)
            if msgs:
                return " ".join(msgs)
        text = (response.text or "").strip()
        return text[:300] if text else f"HTTP {response.status_code}"

    def _upload_script(self, name: str, script_content: str, bindings: List[Dict]) -> requests.Response:
        """Upload the Worker as a classic (service-worker format) script.

        Bindings are included INLINE in the multipart metadata (the documented,
        current way to configure a Worker on upload). The metadata uses
        body_part so Cloudflare compiles the script as classic, never as an ES
        module.
        """
        url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{name}"
        metadata = {
            "body_part": "script",
            "content_type": "application/javascript",
        }
        if bindings:
            metadata["bindings"] = bindings
        files = {
            "metadata": (None, json.dumps(metadata), "application/json"),
            "script": ("worker.js", script_content, "application/javascript"),
        }
        headers = {"Authorization": f"Bearer {self.api_token}"}
        try:
            return requests.put(url, headers=headers, files=files, timeout=90)
        except requests.RequestException as e:
            raise MorpherError(f"Network error while uploading worker {name}: {e}")

    def _upload_error(self, name: str, response: requests.Response) -> MorpherError:
        """Turn a failed upload into an actionable error (real HTTP code + CF message)."""
        detail = self._cf_error(response)
        if response.status_code in (401, 403):
            return MorpherError(
                f"Cloudflare rejected uploading worker '{name}' "
                f"(HTTP {response.status_code}): {detail}. "
                "This is a token/account permission problem: ensure the token has "
                "'Workers Scripts' -> Edit (legacy 'Workers Scripts:Write') permission "
                "AND that account_id belongs to the account the token was created for. "
                "Recreate the token with the 'Edit Cloudflare Workers' template if needed."
            )
        return MorpherError(
            f"Cloudflare rejected uploading worker '{name}' "
            f"(HTTP {response.status_code}): {detail}"
        )

    def deploy_worker(
        self,
        name: str,
        oob: Optional[Dict] = None,
        script_content: Optional[str] = None,
    ) -> Dict:
        """Upload (create or update) a Morpher worker with its OOB bindings."""
        if script_content is None:
            script_content = self.read_worker_script()

        oob = oob or {}
        bindings = self._oob_bindings(oob)

        response = self._upload_script(name, script_content, bindings)
        if response.status_code not in (200, 201):
            raise self._upload_error(name, response)

        try:
            worker_data = response.json()
        except ValueError:
            worker_data = {}

        # Enable the worker on the workers.dev subdomain (critical for access).
        subdomain_url = (
            f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{name}/subdomain"
        )
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    subdomain_url, headers=self.headers, json={"enabled": True}, timeout=30
                )
                if response.status_code in [200, 201]:
                    break
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    print(f"  ⚠ Could not enable worker on subdomain (HTTP {response.status_code})")
            except requests.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    print(f"  ⚠ Could not enable worker on subdomain: {e}")

        worker_url = f"https://{name}.{self.worker_subdomain}.workers.dev"
        return {
            "name": name,
            "url": worker_url,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "id": worker_data.get("result", {}).get("id", name),
        }

    def list_deployments(self) -> List[Dict]:
        """List all Morpher worker deployments."""
        url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise MorpherError(f"Failed to list workers: {e}")

        data = response.json()
        workers = []
        for script in data.get("result") or []:
            name = script.get("id", "")
            if name.startswith(WORKER_PREFIX):
                workers.append(
                    {
                        "name": name,
                        "url": f"https://{name}.{self.worker_subdomain}.workers.dev",
                        "created_at": script.get("created_on", "unknown"),
                    }
                )
        return workers

    # ------------------------------------------------------------- management

    def wait_for_worker_ready(
        self, worker_url: str, max_wait_seconds: int = 600
    ) -> bool:
        """Wait for a worker to be provisioned and reachable over HTTPS."""
        start_time = time.time()
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        spinner_idx = 0

        while time.time() - start_time < max_wait_seconds:
            try:
                requests.get(worker_url, timeout=10, allow_redirects=False)
                return True
            except requests.exceptions.SSLError:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except requests.RequestException:
                return True

            elapsed = int(time.time() - start_time)
            msg = (
                f'\r     {spinner[spinner_idx % len(spinner)]} '
                f'Waiting for worker to be ready... ({elapsed}s)'
            )
            sys.stdout.write(msg)
            sys.stdout.flush()
            spinner_idx += 1
            time.sleep(0.5)

        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        return False

    def delete_workers(self, worker_names: List[str]) -> Dict[str, bool]:
        results = {}
        for name in worker_names:
            url = f"{self.base_url}/accounts/{self.account_id}/workers/scripts/{name}"
            try:
                response = requests.delete(url, headers=self.headers, timeout=30)
                results[name] = response.status_code in [200, 404]
            except requests.RequestException:
                results[name] = False
        return results

    def cleanup_all(self) -> Dict[str, int]:
        """Delete every Morpher worker; returns {deleted, failed} counts."""
        workers = self.list_deployments()
        deleted_count = 0
        failed_count = 0

        if not workers:
            return {"deleted": 0, "failed": 0}

        print(f"  Deleting {len(workers)} worker(s)...\n")
        for i, worker in enumerate(workers, 1):
            url = (
                f"{self.base_url}/accounts/{self.account_id}/workers/scripts/"
                f"{worker['name']}"
            )
            try:
                response = requests.delete(url, headers=self.headers, timeout=30)
                if response.status_code in [200, 404]:
                    print(f"  ✓ [{i}/{len(workers)}] Deleted: {worker['name']}")
                    deleted_count += 1
                else:
                    print(f"  ✗ [{i}/{len(workers)}] Failed: {worker['name']}")
                    failed_count += 1
            except requests.RequestException:
                print(f"  ✗ [{i}/{len(workers)}] Error: {worker['name']}")
                failed_count += 1

        return {"deleted": deleted_count, "failed": failed_count}


class Morpher:
    """Main Morpher manager: config + local state + endpoints."""

    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.cloudflare = self._setup_cloudflare()
        self.endpoints_file = ENDPOINTS_FILE
        self.state_file = STATE_FILE

    # ------------------------------------------------------------ config/state

    def _load_config(self, config_file: Optional[str] = None) -> Dict:
        config = {"cloudflare": {}}

        if config_file and os.path.exists(config_file):
            config = self._load_config_file(config_file, config)

        for default_config in [CONFIG_FILE, os.path.expanduser("~/.morpher.json")]:
            if os.path.exists(default_config):
                config = self._load_config_file(default_config, config)
                break

        return config

    @staticmethod
    def _load_config_file(config_path: str, config: Dict) -> Dict:
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            if "cloudflare" in file_config and not config["cloudflare"]:
                config["cloudflare"].update(file_config["cloudflare"])
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
        return config

    def _setup_cloudflare(self) -> Optional[CloudflareManager]:
        cf_config = self.config.get("cloudflare", {})
        api_token = cf_config.get("api_token")
        account_id = cf_config.get("account_id")
        if api_token and account_id:
            return CloudflareManager(
                api_token=api_token,
                account_id=account_id,
                zone_id=cf_config.get("zone_id"),
            )
        return None

    @property
    def is_configured(self) -> bool:
        return self.cloudflare is not None

    def _load_state(self) -> Dict:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _save_state(self, state: Dict) -> None:
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save state: {e}")

    def _oob_config(self) -> Dict:
        """The current out-of-band logging configuration from local state."""
        state = self._load_state()
        oob = state.get("oob", {})
        domains = oob.get("domains", [])
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        auth = oob.get("auth", "bearer")
        if auth not in ("none", "bearer"):
            auth = "bearer"
        return {
            "url": oob.get("url", ""),
            "auth": auth,
            "token": oob.get("token", ""),
            "domains": [d.strip().lower() for d in domains if d.strip()],
        }

    def _save_endpoints(self, endpoints: List[Dict]) -> None:
        try:
            with open(self.endpoints_file, 'w') as f:
                json.dump(endpoints, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save endpoints: {e}")

    def _load_endpoints(self) -> List[Dict]:
        if os.path.exists(self.endpoints_file):
            try:
                with open(self.endpoints_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def sync_endpoints(self) -> List[Dict]:
        """Sync the local endpoint cache with the remote workers list."""
        if not self.cloudflare:
            return []
        try:
            endpoints = self.cloudflare.list_deployments()
            self._save_endpoints(endpoints)
            return endpoints
        except MorpherError as e:
            print(f"Warning: Could not sync endpoints: {e}")
            return self._load_endpoints()

    # -------------------------------------------------------------- commands

    def set_oob(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        domains: Optional[List[str]] = None,
        auth: Optional[str] = None,
        clear: bool = False,
        redeploy: bool = True,
    ) -> Dict:
        """
        Configure out-of-band logging (listener URL, auth mode, optional
        bearer token, target-domain allowlist) and push it to every endpoint.
        """
        if not self.cloudflare:
            raise MorpherError("Morpher not configured")

        if auth is not None and auth not in ("none", "bearer"):
            raise MorpherError("--auth must be 'none' or 'bearer'")

        state = self._load_state()
        oob = state.get("oob", {})
        if not isinstance(oob, dict):
            oob = {}

        if clear:
            oob = {}
            print("\n  Clearing out-of-band logging configuration...")
        else:
            if url is not None:
                oob["url"] = url.strip() if url.strip() else ""
            if auth is not None:
                oob["auth"] = auth
            if token is not None:
                oob["token"] = token.strip() if token.strip() else ""
            if domains is not None:
                parsed = [d.strip().lower() for d in domains if d.strip()]
                oob["domains"] = parsed

            mode = oob.get("auth", "bearer")
            print("\n  ✓ Out-of-band logging configuration:")
            print(f"    Listener URL: {oob.get('url') or '(disabled - no URL)'}")
            print(f"    Auth mode:    {mode} "
                  f"({'(no Authorization header sent)' if mode == 'none' else 'Bearer token'})")
            if mode == "bearer":
                print(f"    Bearer token: {'(set)' if oob.get('token') else '(none - no auth header)'}")
            print(f"    Domains:      {', '.join(oob.get('domains', [])) or '(all targets)'}")
            if not oob.get("url"):
                print("    -> Logging stays disabled until you set a URL.")

        state["oob"] = oob
        self._save_state(state)

        if not redeploy:
            print("  Saved locally (not yet pushed to Workers). Run: python3 morpher.py update\n")
            return oob

        # Push to existing endpoints.
        workers = self.cloudflare.list_deployments()
        if not workers:
            print("  Saved locally. No endpoints exist yet - run: python3 morpher.py create\n")
            return oob

        print("\n  Redeploying existing endpoints with the new logging config...")
        self.update_workers()
        return oob

    def _deploy(self, name: str, oob: Dict) -> Dict:
        return self.cloudflare.deploy_worker(name=name, oob=oob)

    def create_proxies(self, count: int = 1, name: Optional[str] = None) -> Dict:
        """Create Morpher endpoints (current OOB config is applied automatically).

        Args:
            count: how many endpoints to create (auto-named).
            name: optional custom worker name for a single endpoint. Ignored
                  when count > 1 (names must be unique).
        """
        if not self.cloudflare:
            raise MorpherError("Morpher not configured")

        if name is not None:
            name = normalize_worker_name(name)
            if count != 1:
                raise MorpherError(
                    "--name can only be used with --count 1 "
                    "(each worker needs a unique name)"
                )

        print(f"\n{'=' * 70}")
        print(f"Creating {count} Morpher endpoint{'s' if count != 1 else ''}...")
        print(f"{'=' * 70}")

        oob = self._oob_config()
        results = {"created": [], "failed": 0}

        for i in range(count):
            try:
                worker_name = name or self.cloudflare._generate_worker_name()
                endpoint = self._deploy(worker_name, oob)
                results["created"].append(endpoint)
                print(f"\n  ✓ Worker {i + 1}/{count} created")
                print(f"    Name: {endpoint['name']}")
                print(f"    URL:  {endpoint['url']}")
            except MorpherError as e:
                print(f"\n  ✗ Worker {i + 1}/{count} failed: {e}")
                results["failed"] += 1

        if results["created"]:
            print(f"\n{'-' * 70}")
            print(f"Provisioning worker(s) - can take a few minutes on first run")
            print(f"{'-' * 70}")

            provisioned = []
            for i, endpoint in enumerate(results["created"]):
                print(f"\n  [{i + 1}/{len(results['created'])}] {endpoint['name']}")
                is_ready = self.cloudflare.wait_for_worker_ready(endpoint["url"])
                if is_ready:
                    print("     ✓ Ready!")
                    provisioned.append(endpoint)
                else:
                    print("     ✗ Timeout - worker may still be provisioning")
                    results["failed"] += 1

            results["created"] = provisioned

        self.sync_endpoints()

        print(f"\n{'=' * 70}")
        total_created = len(results["created"])
        if total_created > 0:
            print(f"✓ Successfully created {total_created} worker{'s' if total_created != 1 else ''}")
            for endpoint in results["created"]:
                print(f"  • {endpoint['url']}")
        if results['failed'] > 0:
            print(f"✗ Failed: {results['failed']}")
        print(f"{'=' * 70}\n")

        if oob.get("url"):
            print(f"  Logging is ON - visits to {', '.join(oob['domains']) or 'any target'}")
            print(f"  are batched and POSTed to {oob['url']}\n")
        else:
            print(f"  Logging is OFF. Configure a listener with:")
            print(f"    python3 morpher.py oob --url https://listener.example/hook")
            print(f"                            [--token secret] [--domains example.com]\n")

        return results

    def list_proxies(self) -> List[Dict]:
        """List all deployed Morpher endpoints."""
        endpoints = self.sync_endpoints()
        if not endpoints:
            print(f"\n{'=' * 70}")
            print(f"Morpher Endpoints")
            print(f"{'=' * 70}")
            print("\n  No Morpher endpoints found")
            print("  Create some with: python3 morpher.py create\n")
            return []

        print(f"\n{'=' * 70}")
        print(f"Morpher Endpoints ({len(endpoints)} total)")
        print(f"{'=' * 70}\n")

        for i, endpoint in enumerate(endpoints, 1):
            print(f"  {i}. {endpoint.get('name', 'unknown')}")
            print(f"     URL: {endpoint.get('url', 'unknown')}")
            print(f"     Status: Active\n")

        return endpoints

    def show_oob(self) -> None:
        """Print the current out-of-band logging configuration."""
        oob = self._oob_config()
        print(f"\n{'=' * 70}")
        print(f"Out-of-band Logging")
        print(f"{'=' * 70}\n")
        print(f"  Listener URL: {oob['url'] or '(not set - logging disabled)'}")
        print(f"  Auth mode:    {oob['auth']} "
              f"({'(no Authorization header sent)' if oob['auth'] == 'none' else 'Bearer token'})")
        if oob['auth'] == 'bearer':
            print(f"  Bearer token: {'(set)' if oob.get('token') else '(none - no auth header)'}")
        print(f"  Domains:      {', '.join(oob['domains']) or '(all targets)'}")
        print(f"\n  Change with:  python3 morpher.py oob --url ... [--auth none|bearer] "
              f"[--token ...] [--domains ...]")
        print(f"  Disable with: python3 morpher.py oob --clear")
        print(f"\n  Batches are POSTed as JSON arrays. Example single entry:")
        print(f"    {{\"ts\": 1710000000000, \"ip\": \"203.0.113.7\", \"xff\": \"91.5.1.2\",")
        print(f"     \"method\": \"GET\", \"target\": \"https://example.com/x\",")
        print(f"     \"host\": \"example.com\", \"status\": 200, \"via\": \"morpher-...workers.dev\",")
        print(f"     \"ua\": \"curl/8.4\"}}")
        print(f"\n  Domains support wildcards: '*.example.com' matches subdomains only,")
        print(f"  plain 'example.com' matches the apex and all subdomains.\n")

    def update_workers(self) -> Dict:
        """
        Redeploy worker.js to every existing Morpher endpoint. Use this after
        editing worker.js (e.g. tuning CONFIG batching) or after changing OOB
        config via the 'oob' command (which also calls this).
        """
        if not self.cloudflare:
            raise MorpherError("Morpher not configured")

        workers = self.cloudflare.list_deployments()
        if not workers:
            print("\n  No Morpher endpoints to update. Create some with:\n"
                  "    python3 morpher.py create\n")
            return {"updated": 0, "failed": 0}

        print(f"\n{'=' * 70}")
        print(f"Updating {len(workers)} Morpher endpoint{'s' if len(workers) != 1 else ''}...")
        print(f"{'=' * 70}\n")

        oob = self._oob_config()
        results = {"updated": 0, "failed": 0}
        script_content = self.cloudflare.read_worker_script()

        for i, worker in enumerate(workers, 1):
            try:
                self.cloudflare.deploy_worker(
                    name=worker["name"],
                    oob=oob,
                    script_content=script_content,
                )
                print(f"  ✓ [{i}/{len(workers)}] Updated: {worker['name']}")
                results["updated"] += 1
            except MorpherError as e:
                print(f"  ✗ [{i}/{len(workers)}] Failed: {worker['name']} ({e})")
                results["failed"] += 1

        self.sync_endpoints()
        print(f"\n  Summary: {results['updated']} updated, {results['failed']} failed\n")
        return results

    def rename_worker(self, old: str, new: str) -> Dict:
        """
        Rename an existing Morpher endpoint. Cloudflare has no rename API, so
        this deploys a new worker under the new name with the current OOB
        config, waits until it is live, then deletes the old worker.
        """
        if not self.cloudflare:
            raise MorpherError("Morpher not configured")

        new_name = normalize_worker_name(new)
        old_name = normalize_worker_name(old)

        workers = self.cloudflare.list_deployments()
        if not workers:
            raise MorpherError(
                "No Morpher endpoints found. Create some with: python3 morpher.py create"
            )

        names = [w["name"] for w in workers]
        old_match = next((w["name"] for w in workers if w["name"] == old_name), None)
        if old_match is None:
            raise MorpherError(
                f"No endpoint named '{old_name}' found. Current endpoints: {', '.join(names)}"
            )
        if new_name == old_match:
            raise MorpherError(f"'{new_name}' is already the name of that endpoint")
        if new_name in names:
            raise MorpherError(
                f"An endpoint named '{new_name}' already exists - pick another name"
            )

        oob = self._oob_config()
        print(f"\n  Deploying replacement worker '{new_name}' (same OOB config)...")
        endpoint = self._deploy(new_name, oob)
        print(f"    Created: {endpoint['url']}")

        is_ready = self.cloudflare.wait_for_worker_ready(endpoint["url"])
        if not is_ready:
            raise MorpherError(
                f"New worker '{new_name}' is not responding yet - the old worker "
                f"'{old_match}' was NOT deleted. Re-run to finish or check manually."
            )
        print("    ✓ New worker is live")

        print(f"  Deleting old worker '{old_match}'...")
        results = self.cloudflare.delete_workers([old_match])
        if not results.get(old_match):
            raise MorpherError(
                f"Could not delete old worker '{old_match}'. It still exists; "
                f"run 'python3 morpher.py cleanup' or delete it in the dashboard."
            )
        print(f"    ✓ Deleted old worker")

        self.sync_endpoints()
        print(f"\n  ✓ Renamed {old_match} -> {new_name}")
        print(f"    New URL: {endpoint['url']}\n")
        return {"old": old_match, "new": new_name, "url": endpoint["url"]}

    def test_proxies(self, target_url: str = "https://httpbin.org/headers", method: str = "GET") -> Dict:
        """Test every endpoint and show the X-Morph-Real-Ip the origin received."""
        endpoints = self._load_endpoints()
        if not endpoints:
            print(f"\n{'=' * 70}")
            print(f"Test Morpher Endpoints")
            print(f"{'=' * 70}")
            print("\n  No proxy endpoints available. Create some first.\n")
            return {"success": False, "error": "No endpoints available"}

        print(f"\n{'=' * 70}")
        print(f"Testing {len(endpoints)} Morpher endpoint{'s' if len(endpoints) != 1 else ''}")
        print(f"{'=' * 70}")
        print(f"\n  Target URL: {target_url}")
        print(f"  Method: {method}\n")
        print(f"{'-' * 70}")

        successful = 0
        results = {}

        for i, endpoint in enumerate(endpoints, 1):
            name = endpoint.get("name", "unknown")
            print(f"\n  [{i}/{len(endpoints)}] {name}")

            result = {"success": False, "error": "Unknown error"}
            try:
                test_url = f"{endpoint['url']}?url={target_url}"
                response = requests.request(method, test_url, timeout=45)

                if response.status_code != 200:
                    print(f"     ✗ Request failed (Status: {response.status_code})")
                    result = {"success": False, "status_code": response.status_code}
                    results[name] = result
                    continue

                successful += 1
                result = {
                    "success": True,
                    "status_code": 200,
                    "response_length": len(response.content),
                }

                real_ip = None
                masked_xff = None
                try:
                    data = response.json()
                    headers = data.get("headers", {})
                    real_ip = headers.get("X-Morph-Real-Ip")
                    masked_xff = headers.get("X-Forwarded-For")
                except (ValueError, AttributeError):
                    pass

                print("     ✓ Request successful (Status: 200)")
                if real_ip:
                    print(f"       Real IP forwarded (X-Morph-Real-Ip): {real_ip}")
                else:
                    text = response.text.strip()
                    snippet = text[:80] if text else ""
                    print(f"       Response: {snippet or result['response_length']} bytes")
                if masked_xff:
                    print(f"       Masked X-Forwarded-For origin saw: {masked_xff}")
            except requests.RequestException as e:
                print(f"     ✗ Request failed: {e}")
                result = {"success": False, "error": str(e)}

            results[name] = result

        print(f"\n{'-' * 70}")
        print(f"  ✓ Working: {successful}/{len(endpoints)}")
        if successful < len(endpoints):
            print(f"  ✗ Failed: {len(endpoints) - successful}")
        print(f"{'-' * 70}\n")

        return results

    def cleanup(self, purge: bool = False) -> None:
        """Delete all Morpher endpoints (--purge also removes local state)."""
        if not self.cloudflare:
            raise MorpherError("Morpher not configured")

        summary = self.cloudflare.cleanup_all()
        print(f"\n  Summary: {summary['deleted']} deleted, {summary['failed']} failed")

        if os.path.exists(self.endpoints_file):
            try:
                os.remove(self.endpoints_file)
                print("  ✓ Local endpoint cache cleared")
            except OSError:
                pass

        if purge:
            for path in [self.state_file, self.endpoints_file]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                        print(f"  ✓ Removed {path}")
                    except OSError:
                        pass
            print("  ✓ Purge complete")


# ---------------------------------------------------------------------- CLI


def setup_interactive_config() -> bool:
    """Interactive setup for Cloudflare credentials."""
    print(f"\n{'=' * 70}")
    print(f"Morpher Setup - Cloudflare Credentials")
    print(f"{'=' * 70}\n")
    print("  Getting Cloudflare Credentials:\n")
    print("  1. Sign up at https://cloudflare.com")
    print("  2. Go to https://dash.cloudflare.com/profile/api-tokens")
    print("  3. Click 'Create Token' and use the 'Edit Cloudflare Workers' template")
    print("     (only 'Workers Scripts' -> Edit is required - no KV needed).")
    print("  4. Set 'account resources' and 'zone resources' to All. Continue.")
    print("  5. Click 'Create Token'; copy the token and your Account ID.\n")
    print(f"{'-' * 70}\n")

    api_token = getpass.getpass("  Enter your Cloudflare API token: ").strip()
    if not api_token:
        print("\n  ✗ API token is required\n")
        return False

    account_id = input("  Enter your Cloudflare Account ID: ").strip()
    if not account_id:
        print("\n  ✗ Account ID is required\n")
        return False

    config = {"cloudflare": {"api_token": api_token, "account_id": account_id}}

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except IOError as e:
        print(f"\n  ✗ Error saving configuration: {e}\n")
        return False

    print(f"\n{'=' * 70}")
    print(f"✓ Configuration Saved")
    print(f"{'=' * 70}")
    print(f"  Config file: {CONFIG_FILE}")
    print(f"  Morpher is ready. Deploy endpoints with:")
    print(f"    python3 morpher.py create\n")
    return True


def show_config_help() -> None:
    print(f"\n{'=' * 70}")
    print(f"Morpher Configuration")
    print(f"{'=' * 70}")

    config_files = [CONFIG_FILE, os.path.expanduser("~/.morpher.json")]
    existing_config_files = []
    valid_config_found = False

    for config_file in config_files:
        if os.path.exists(config_file):
            existing_config_files.append(config_file)
            try:
                with open(config_file, 'r') as f:
                    cf_config = json.load(f).get("cloudflare", {})
                    api_token = cf_config.get("api_token", "").strip()
                    account_id = cf_config.get("account_id", "").strip()
                    if (
                        api_token
                        and account_id
                        and len(api_token) > 10
                        and len(account_id) > 10
                    ):
                        valid_config_found = True
                        break
            except (json.JSONDecodeError, IOError):
                continue

    if valid_config_found:
        print(f"\n  ✓ Morpher is already configured with valid credentials.\n")
        for config_file in existing_config_files:
            print(f"    - {config_file}")
        choice = input("\n  Reconfigure? (y/n): ").strip().lower()
        if choice != 'y':
            print()
            return

    print("\n  Setting up Morpher configuration...\n")
    if setup_interactive_config():
        print("  You can now use Morpher:")
        print("    python3 morpher.py create --count 2")
        print("    python3 morpher.py oob --url https://listener.example/hook\n")
    else:
        print("\n  ✗ Configuration failed. Please try again.\n")


def show_help_message() -> None:
    print(f"\n{'=' * 70}")
    print(f"Morpher - Forwarding proxies on Cloudflare Workers with OOB visit logging")
    print(f"{'=' * 70}\n")
    print(f"  Usage: python3 morpher.py <command> [options]\n")
    print(f"{'-' * 70}")
    print(f"Commands:")
    print(f"{'-' * 70}\n")
    print(f"  config    Show configuration help and set up credentials")
    print(f"  create    Create new proxy endpoints (--count N, --name for a custom name)")
    print(f"  list      List all proxy endpoints")
    print(f"  oob       Configure out-of-band visit logging (listener, token, domains)")
    print(f"  test      Test endpoints; shows the X-Morph-Real-Ip the origin received")
    print(f"  update    Re-deploy worker.js to existing endpoints")
    print(f"  rename    Rename an endpoint (--endpoint OLD --name NEW)")
    print(f"  cleanup   Delete all proxy endpoints (--purge also removes local state)")
    print(f"  help      Show detailed help\n")
    print(f"{'-' * 70}")
    print(f"Examples:")
    print(f"{'-' * 70}\n")
    print(f"  python3 morpher.py config")
    print(f"  python3 morpher.py create --count 2")
    print(f"  python3 morpher.py create --name myproxy")
    print(f"  python3 morpher.py rename --endpoint myproxy --name proxy-eu")
    print(f"  python3 morpher.py oob --url https://listener.example/hook \\")
    print(f"                          --token secret --domains example.com,*.api.example.com")
    print(f"  python3 morpher.py oob --url https://listener.example/hook --auth none")
    print(f"  python3 morpher.py test\n")


def show_detailed_help() -> None:
    print(f"\n{'=' * 70}")
    print(f"Morpher - Detailed Help")
    print(f"{'=' * 70}\n")
    print(f"  Morpher deploys Cloudflare Workers that forward any URL through")
    print(f"  Cloudflare's network, exactly like FlareProx, plus:\n")
    print(f"  1. Out-of-band visit logging:")
    print(f"     When a proxied request is heading to one of your configured target")
    print(f"     domains, the Worker buffers a log entry and POSTs it to your own")
    print(f"     listener (webhook) in batches. No KV, no Cloudflare-side storage.\n")
    print(f"     Each entry contains: real IP (the peer Cloudflare saw connect), the")
    print(f"     masked X-Forwarded-For the origin saw, method, target URL, target")
    print(f"     host, status code, the endpoint (via) and user-agent. Failed")
    print(f"     requests (origin down / 5xx) are logged too.\n")
    print(f"     Domains support wildcards: 'example.com' matches the apex and all")
    print(f"     subdomains; '*.example.com' matches subdomains only (never the apex).\n")
    print(f"     Auth: '--auth none' POSTs without an Authorization header (open")
    print(f"     listener); '--auth bearer' (default) sends the optional --token as")
    print(f"     'Authorization: Bearer ...'.\n")
    print(f"     Config (URL, auth mode, optional token, domain allowlist) is stored in")
    print(f"     the local morpher_state.json and injected as Worker bindings, so no")
    print(f"     secrets end up in git. Batching knobs (oobBatchSize, oobFlushEveryMs,")
    print(f"     oobMaxBuffered) live in CONFIG at the top of worker.js.\n")
    print(f"  2. X-Morph-Real-Ip header:")
    print(f"     When forwarding to the target, the worker adds the real connecting IP")
    print(f"     as 'X-Morph-Real-Ip'. By default that is CF-Connecting-IP (authoritative,")
    print(f"     cannot be forged). Set CONFIG.trustChainedRealIp to true only when you")
    print(f"     chain your own Morpher hops and want the outermost real IP preserved.\n")
    print(f"  Usage notes:")
    print(f"    - Your API token needs only 'Workers Scripts' -> Edit.\n")


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Morpher - Cloudflare Workers forwarding proxies with OOB visit logging"
    )

    parser.add_argument(
        "command",
        nargs='?',
        choices=["create", "list", "oob", "test", "update", "rename", "cleanup", "help", "config"],
        help="Command to execute",
    )
    parser.add_argument("--url", help="Target URL for tests, or the OOB listener URL")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--count", type=int, default=1, help="Number of proxies to create (default: 1)")
    parser.add_argument("--name", help="Custom worker name for a single endpoint (use with --count 1) "
                                      "or the NEW name for 'rename'")
    parser.add_argument("--endpoint", help="Existing worker name to rename (with 'rename')")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--token", help="OOB listener bearer token")
    parser.add_argument("--auth", choices=["none", "bearer"],
                        help="OOB listener auth mode: 'none' (no Authorization header) "
                             "or 'bearer' (default)")
    parser.add_argument("--domains", help="Comma-separated target-domain allowlist for OOB logging "
                                          "(supports *.example.com wildcards)")
    parser.add_argument("--clear", action="store_true", help="With 'oob': disable out-of-band logging")
    parser.add_argument("--no-redeploy", action="store_true",
                        help="With 'oob': save config locally without redeploying endpoints")
    parser.add_argument("--purge", action="store_true",
                        help="With cleanup: also delete local state")

    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.command:
        show_help_message()
        return

    if args.command == "config":
        show_config_help()
        return

    if args.command == "help":
        show_detailed_help()
        return

    try:
        morpher = Morpher(config_file=args.config)
    except Exception as e:
        print(f"\n  ✗ Configuration error: {e}\n")
        return

    if not morpher.is_configured:
        print(f"\n{'=' * 70}")
        print(f"Morpher Not Configured")
        print(f"{'=' * 70}\n")
        print(f"  Run 'python3 morpher.py config' to set up Morpher\n")
        return

    try:
        if args.command == "create":
            morpher.create_proxies(args.count, name=args.name)

        elif args.command == "list":
            morpher.list_proxies()

        elif args.command == "oob":
            if args.clear:
                morpher.set_oob(clear=True, redeploy=not args.no_redeploy)
            else:
                domains = None
                if args.domains is not None:
                    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
                if args.url is None and args.token is None and args.auth is None and domains is None:
                    morpher.show_oob()
                else:
                    morpher.set_oob(
                        url=args.url,
                        token=args.token,
                        domains=domains,
                        auth=args.auth,
                        redeploy=not args.no_redeploy,
                    )

        elif args.command == "test":
            if args.url:
                morpher.test_proxies(args.url, args.method)
            else:
                morpher.test_proxies()

        elif args.command == "update":
            morpher.update_workers()

        elif args.command == "rename":
            if not args.endpoint or not args.name:
                raise MorpherError(
                    "Usage: python3 morpher.py rename --endpoint OLD_NAME --name NEW_NAME"
                )
            if not args.yes:
                print(f"\n  Renaming worker '{args.endpoint}' -> '{args.name}'.")
                print("  This deploys a new worker, waits for it, then DELETES the old one.")
                confirm = input("  Continue? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("\n  Rename cancelled.\n")
                    return
            morpher.rename_worker(args.endpoint, args.name)

        elif args.command == "cleanup":
            print(f"\n{'=' * 70}")
            print(f"Cleanup All Morpher Endpoints")
            print(f"{'=' * 70}\n")
            proceed = args.yes
            if not proceed:
                proceed = input("  Delete ALL Morpher endpoints? (y/N): ").strip().lower() == 'y'
            if proceed:
                morpher.cleanup(purge=args.purge)
            else:
                print("\n  Cleanup cancelled.\n")
    except MorpherError as e:
        print(f"\n  ✗ Error: {e}\n")
    except KeyboardInterrupt:
        print("\n\n  Operation cancelled by user\n")
    except Exception as e:
        print(f"\n  ✗ Unexpected error: {e}\n")


if __name__ == "__main__":
    main()
