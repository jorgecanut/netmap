import unittest

from netmap_core import rules
from netmap_core.rules import Ctx, RuleError, compile_rule, evaluate


def ctx(**over):
    base = {k: "" for k in rules.FIELDS}
    base.update(lists=[], threat_severity=0, bytes_out=0, bytes_in=0, duration=0,
                remote_port=443, local_port=50000, hour=12, weekday=0, closed=False,
                new_country=False, new_remote=False)
    base.update(over)
    return Ctx(base)


def run(expr, **over):
    return evaluate(compile_rule(expr), ctx(**over))


class Language(unittest.TestCase):
    def test_comparisons_and_logic(self):
        self.assertTrue(run('subnet == "iot" and direction == "out"', subnet="iot", direction="out"))
        self.assertFalse(run('subnet == "iot" and not new_country', subnet="iot", new_country=True))
        self.assertTrue(run("remote_port in (22, 23, 2323)", remote_port=23))
        self.assertTrue(run('country not in ("ES", "PT")', country="RU"))
        self.assertTrue(run("1000 < remote_port < 2000", remote_port=1500))
        self.assertTrue(run("bytes_out > 10 * 1024 * 1024", bytes_out=20 * 1048576))
        self.assertTrue(run("threat_severity >= medium", threat_severity=4))
        self.assertTrue(run('"tor" in lists', lists=["tor"]))

    def test_functions(self):
        self.assertTrue(run('ends(domain, ".RU")', domain="evil.example.ru"))
        self.assertTrue(run('contains(org, "amazon")', org="Amazon.com, Inc."))
        self.assertTrue(run('in_net(remote_ip, "10.0.0.0/8")', remote_ip="10.1.2.3"))
        self.assertFalse(run('in_net(remote_ip, "not a net")', remote_ip="10.1.2.3"))

    def test_lazy_fields_only_computed_when_used(self):
        calls = []
        c = ctx(subnet="lan", new_country=lambda: calls.append(1) or True)
        evaluate(compile_rule('subnet == "iot" and new_country'), c)
        self.assertEqual(calls, [])                       # short-circuit: never asked
        self.assertTrue(evaluate(compile_rule("new_country"), c))
        self.assertEqual(calls, [1])


class Safety(unittest.TestCase):
    def assertRejected(self, expr, fragment):
        with self.assertRaises(RuleError) as cm:
            compile_rule(expr)
        self.assertIn(fragment, str(cm.exception))

    def test_no_code_execution(self):
        self.assertRejected('__import__("os").system("id")', "unknown")
        self.assertRejected("open('/etc/passwd')", "unknown")
        self.assertRejected("domain.__class__", "Attribute")
        self.assertRejected("[x for x in lists]", "ListComp")
        self.assertRejected("lambda: 1", "Lambda")
        self.assertRejected("lists[0]", "Subscript")
        self.assertRejected("2 ** 999999", "Pow")
        self.assertRejected("x := 1", "")
        self.assertRejected('ends(domain, suffix=".ru")', "plain arguments")

    def test_unknown_names_and_syntax(self):
        self.assertRejected("subnett == 'iot'", "unknown name 'subnett'")
        self.assertRejected("subnet == ", "syntax error")
        self.assertRejected("", "empty")
        self.assertRejected("a" * 3000, "longer")

    def test_string_multiplication_blocked_at_runtime(self):
        with self.assertRaises(TypeError):
            run('domain * 1000000 == ""', domain="x")

    def test_error_has_column(self):
        with self.assertRaises(RuleError) as cm:
            compile_rule('subnet == "iot" and bogus')
        self.assertEqual(cm.exception.col, 21)


class Engine(unittest.TestCase):
    def test_broken_rule_does_not_stop_others(self):
        class FakeStore:
            def rules(self, enabled_only=False):
                return [{"id": 1, "name": "bad", "expr": "remote_port > 'x'", "category": "c",
                         "severity": 2},
                        {"id": 2, "name": "good", "expr": "remote_port == 443",
                         "category": "c", "severity": 3}]
        e = rules.Engine(FakeStore())
        e.reload()
        flags = e.run(ctx())
        self.assertEqual([f["name"] for f in flags], ["good"])
        self.assertEqual(e.errors[1]["count"], 1)
        self.assertIn("TypeError", e.errors[1]["last"])


class Docs(unittest.TestCase):
    def test_every_example_in_rules_md_compiles(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docs", "RULES.md")
        with open(path, encoding="utf-8") as f:
            block = f.read().split("## Examples")[1].split("```python")[1].split("```")[0]
        examples = [l.strip() for l in block.splitlines()
                    if l.strip() and not l.strip().startswith("#")]
        self.assertGreater(len(examples), 5)
        for e in examples:
            compile_rule(e)

    def test_every_field_is_documented(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "docs", "RULES.md")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for field in rules.FIELDS:
            self.assertIn("`%s`" % field, text, "field %s missing from RULES.md" % field)


if __name__ == "__main__":
    unittest.main()
