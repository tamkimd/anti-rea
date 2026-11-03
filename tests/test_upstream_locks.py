import gzip
import hashlib
import json
from pathlib import Path
import unittest


ROOT=Path(__file__).parents[1]


class UpstreamLockTests(unittest.TestCase):
    def test_recorded_lock_hashes_and_direct_package_identities_match(self):
        data=json.loads((ROOT/"locks/upstreams.json").read_text())
        for name in ("rea","e2e","bla"):
            item=data["integrations"][name]
            lock_path=ROOT/item["package_lock"]
            payload=lock_path.read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(),item["package_lock_sha256"])
            lock=json.loads(payload)
            expected={"rea-agents":item["npm_version"]} if name=="rea" else (
                {"bla-agents":item["npm_version"]} if name=="bla" else {k:v["version"] for k,v in item["packages"].items()})
            for package,version in expected.items():
                self.assertEqual(lock["packages"][f"node_modules/{package}"]["version"],version)
                integrity=item["npm_integrity"] if name in {"rea","bla"} else item["packages"][package]["integrity"]
                self.assertEqual(lock["packages"][f"node_modules/{package}"]["integrity"],integrity)

    def test_runtime_tool_schema_snapshot_is_pinned_and_explicitly_scoped(self):
        data=json.loads((ROOT/"locks/upstreams.json").read_text())
        rea=data["integrations"]["rea"]
        path=ROOT/rea["runtime_tool_contracts"]
        payload=path.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(),rea["runtime_tool_contracts_sha256"])
        inventory=json.loads(gzip.decompress(payload))
        self.assertEqual(inventory["upstream"]["source_commit"],rea["source_commit"])
        self.assertEqual(inventory["upstream"]["npm_integrity"],rea["npm_integrity"])
        self.assertEqual(inventory["tool_count"],len(inventory["tools"]))
        self.assertEqual(len({tool["name"] for tool in inventory["tools"]}),inventory["tool_count"])
        self.assertTrue(all(isinstance(tool.get("inputSchema"),dict) for tool in inventory["tools"]))
        self.assertTrue(any("source-only" in limit for limit in inventory["limitations"]))

    def test_rea_source_runtime_ledger_binds_tools_prompts_and_cli(self):
        rea=json.loads((ROOT/"locks/upstreams.json").read_text())["integrations"]["rea"]
        path=ROOT/rea["source_runtime_ledger"]
        raw=path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),rea["source_runtime_ledger_sha256"])
        ledger=json.loads(raw)
        self.assertEqual(ledger["record_type"],"upstream_source_runtime_ledger")
        self.assertEqual(ledger["upstream"]["source_commit"],rea["source_commit"])
        for kind in ("mcp_tools","mcp_prompts","cli_commands"):
            source=ledger["source"][kind]
            runtime=ledger["runtime"][kind]
            self.assertEqual(source,runtime)
            self.assertEqual(ledger["comparisons"]["mcp_prompts_workflows" if kind=="mcp_prompts" else kind],
                             {"source_only":[],"runtime_only":[],"matching_count":len(source)})
        self.assertEqual(len(ledger["source"]["mcp_tools"]),229)
        self.assertEqual(len(ledger["source"]["mcp_prompts"]),6)
        self.assertEqual(len(ledger["source"]["cli_commands"]),175)

        prompt_path=ROOT/rea["runtime_prompt_contracts"]
        prompt_raw=prompt_path.read_bytes()
        self.assertEqual(hashlib.sha256(prompt_raw).hexdigest(),rea["runtime_prompt_contracts_sha256"])
        prompts=json.loads(prompt_raw)
        self.assertEqual(prompts["upstream"]["source_commit"],rea["source_commit"])
        self.assertEqual([item["name"] for item in prompts["prompts"]],ledger["runtime"]["mcp_prompts"])

    def test_rea_capability_readiness_is_pinned_and_fixture_scoped(self):
        rea=json.loads((ROOT/"locks/upstreams.json").read_text())["integrations"]["rea"]
        path=ROOT/rea["capability_readiness_ledger"]
        raw=path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),rea["capability_readiness_ledger_sha256"])
        ledger=json.loads(raw)
        self.assertEqual(ledger["record_type"],"upstream_capability_readiness")
        for key,lock_key in (("package","npm_package"),("version","npm_version"),
                             ("source_commit","source_commit"),("npm_integrity","npm_integrity"),
                             ("package_lock_sha256","package_lock_sha256"),
                             ("runtime_tool_contracts_sha256","runtime_tool_contracts_sha256"),
                             ("source_runtime_ledger_sha256","source_runtime_ledger_sha256")):
            self.assertEqual(ledger["upstream"][key],rea[lock_key])

        run_path=ROOT/ledger["evidence"]["fixture_run"]["path"]
        self.assertEqual(hashlib.sha256(run_path.read_bytes()).hexdigest(),ledger["evidence"]["fixture_run"]["sha256"])
        run=json.loads(run_path.read_text())
        checks={item["name"]:item for item in ledger["provider_checks"]}
        self.assertEqual(len(checks),ledger["evidence"]["doctor"]["check_count"])
        self.assertEqual(ledger["evidence"]["doctor"]["status"],run["doctor"]["status"])
        self.assertEqual(ledger["evidence"]["doctor"]["report_sha256"],run["doctor"]["sha256"])
        failed_checks=sorted(name for name,item in checks.items() if not item["ok"])
        self.assertEqual(sorted(ledger["evidence"]["doctor"]["failed_check_names"]),failed_checks)
        tool_snapshot=json.loads(gzip.decompress((ROOT/rea["runtime_tool_contracts"]).read_bytes()))
        tool_names={tool["name"] for tool in tool_snapshot["tools"]}
        evidence_ids={run["cli_analysis"]["evidence_id"],run["mcp_analysis"]["evidence_id"]}
        allowed={"verified_fixture","blocked","unknown","not_supported"}
        for family in ledger["target_families"]:
            for capability in family["capabilities"]:
                self.assertIn(capability["status"],allowed)
                self.assertTrue(set(capability["provider_check_names"]) <= set(checks))
                if capability["status"]=="verified_fixture":
                    self.assertTrue(set(capability["evidence_ids"]) <= evidence_ids)
                    self.assertTrue(capability["rea_tool_names"])
                    self.assertTrue(set(capability["rea_tool_names"]) <= tool_names)
        for provider in ledger["providers"]:
            self.assertIn(provider["doctor_check"],checks)
            if not checks[provider["doctor_check"]]["ok"]:
                self.assertFalse(provider["available"])
        self.assertEqual(ledger["evidence"]["doctor"]["status"],"incomplete")
        self.assertFalse(any(provider["available"] for provider in ledger["providers"]))


if __name__=="__main__":
    unittest.main()
