import unittest

import lab

TRACE = """\
100   1700000000.100000 openat(AT_FDCWD, "/srv/dvwa/vulnerabilities/exec/index.php", O_RDONLY) = 4
100   1700000000.110000 connect(5, {sa_family=AF_INET, sin_port=htons(3306), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
101   1700000000.120000 execve("/usr/bin/sh", ["sh", "-c", "ping -c 4 1"], 0x0 /* 3 vars */ <unfinished ...>
101   1700000000.130000 <... execve resumed>) = 0
102   1700000000.140000 execve("/usr/local/bin/id", ["id"], 0x0) = -1 ENOENT (No such file or directory)
102   1700000000.150000 execve("/usr/bin/id", ["id"], 0x0) = 0
102   1700000000.160000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
102   1700000000.170000 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
100   1700000005.000000 openat(AT_FDCWD, "/srv/dvwa/index.php", O_RDONLY) = 4
"""


class StraceTests(unittest.TestCase):
    def test_parse(self):
        calls = lab.parse_strace(TRACE)
        self.assertEqual([c.call for c in calls], ["openat", "connect", "execve", "execve", "execve", "openat",
                                                   "connect", "openat"])
        self.assertTrue(calls[2].ok)
        self.assertFalse(calls[3].ok)
        self.assertEqual(calls[1].arg, "inet:127.0.0.1:3306")
        self.assertEqual(calls[6].arg, "unix:/var/run/nscd/socket")
        self.assertFalse(calls[6].ok)

    def test_attribute_by_time(self):
        calls = lab.parse_strace(TRACE)
        a = lab.Exchange("benign", "exec", "POST", "/vulnerabilities/exec/", {"ip": "1"}, 1700000000.05, 1700000000.2)
        b = lab.Exchange("benign", "static", "GET", "/index.php", {}, 1700000004.9, 1700000005.1)
        per = lab.attribute([a, b], calls)
        self.assertEqual(len(per[0]), 7)
        self.assertEqual(len(per[1]), 1)

    def test_unseen_against_vocab(self):
        calls = lab.parse_strace(TRACE)
        e = lab.Exchange("attack", "cmdi", "POST", "/vulnerabilities/exec/", {"ip": "1; id"}, 1700000000.05,
                         1700000000.2, 200, "x")
        v = lab.Vocab(paths=["/vulnerabilities/exec/"], exes={"sh", "ping"}, endpoints={"inet:127.0.0.1:3306"},
                      files={"<docroot>/vulnerabilities/exec/index.php"}, chars={"."})
        f = lab.features(e, lab.attribute([e], calls)[0], v, "/srv/dvwa")
        self.assertEqual(f["process"], [2.0, 2.0, 1.0, 1.0])
        self.assertEqual(f["network"][:3], [2.0, 2.0, 1.0])
        self.assertEqual(f["file"][2], 1.0)
        self.assertEqual(f["request"][5], 2.0)  # ';' and ' ' unseen
        self.assertEqual(len(f["correlated"]), len(f["request"]) + 12)

    def test_norm_path(self):
        self.assertEqual(lab.norm_path("/proc/1234/status", "/srv"), "/proc/N/status")
        self.assertEqual(lab.norm_path("/var/lib/php/sessions/sess_ab12", "/srv"), "/var/lib/php/sessions/sess_X")


class OracleTests(unittest.TestCase):
    def test_sqli_needs_rows_beyond_legit(self):
        legit = {"1": {("admin", "admin")}}
        body = "First name: admin<br />Surname: admin</pre>First name: Gordon<br />Surname: Brown</pre>"
        ex = lab.Exchange("attack", "sqli", "GET", "/", {"id": "1' OR '1'='1"}, body=body)
        self.assertTrue(lab.judge(ex, legit, None, {}))
        ex.body = "First name: admin<br />Surname: admin</pre>"
        self.assertFalse(lab.judge(ex, legit, None, {}))

    def test_whoami_and_canary(self):
        facts = {"uname": "Linux box", "user": "runner", "hostname": "box"}
        ex = lab.Exchange("attack", "cmdi", "POST", "/", {"ip": "; whoami"}, body="<pre>runner\n</pre>")
        self.assertTrue(lab.judge(ex, {}, None, facts))

        class C:
            def saw(self, t):
                return t == "ps1"
        ex2 = lab.Exchange("attack", "cmdi", "POST", "/", {"ip": "x"}, body="", token="ps1")
        self.assertTrue(lab.judge(ex2, {}, C(), facts))
        ex2.token = "ps2"
        self.assertFalse(lab.judge(ex2, {}, C(), facts))


if __name__ == "__main__":
    unittest.main()
