"""Pure rules tests; no Docker or production input."""

import json
import sys
import unittest
from pathlib import Path

OPS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OPS))
import stools_db_masking as mask


def rules(**kwargs):
    return mask.Rules(
        {
            "format": "stools-db-anonymize/1",
            "replacements": [
                {"from": "corp.example", "to": "lab.example"},
                {"from": "alice", "to": "user-001"},
            ],
            "networks": [{"from": "10.10.0.0/16", "to": "10.200.0.0/16"}],
            **kwargs,
        }
    )


class RulesTests(unittest.TestCase):
    def test_consistent_names_domains_and_addresses(self):
        r = rules()
        self.assertEqual(
            r.text("alice@corp.example 10.10.5.7"), "user-001@lab.example 10.200.5.7"
        )
        self.assertEqual(
            r.text("CN=alice,DC=corp,DC=example"), "CN=user-001,DC=corp,DC=example"
        )
        self.assertEqual(r.text("10.10.5.7/24"), "10.200.5.7/24")
        self.assertEqual(r.text("10.0.0.0/8"), "10.0.0.0/8")

    def test_domains_are_explicit_not_implicit_directory_guessing(self):
        r = rules(
            replacements=[{"from": "DC=corp,DC=example", "to": "DC=lab,DC=example"}]
        )
        self.assertEqual(
            r.text("OU=Users,DC=corp,DC=example"), "OU=Users,DC=lab,DC=example"
        )

    def test_range_and_versions(self):
        r = rules()
        self.assertEqual(r.text("10.10.1.1-10.10.1.20"), "10.200.1.1-10.200.1.20")
        self.assertEqual(r.text("10.10.1.2", addresses=False), "10.10.1.2")
        with self.assertRaises(mask.MaskError):
            r.text("10.10.0.0/15")
        with self.assertRaises(mask.MaskError):
            r.text("10.10.1.1-10.11.1.20")
        with self.assertRaises(mask.MaskError):
            r.text("10.200.5.7")

    def test_config_collisions_and_unknown_fields(self):
        for change in [
            {
                "replacements": [
                    {"from": "one", "to": "alias"},
                    {"from": "two", "to": "alias"},
                ]
            },
            {
                "replacements": [
                    {"from": "one", "to": "two"},
                    {"from": "two", "to": "three"},
                ]
            },
            {"networks": [{"from": "10.10.0.0/16", "to": "10.200.0.0/24"}]},
            {
                "networks": [
                    {"from": "10.10.0.0/16", "to": "10.200.0.0/16"},
                    {"from": "10.11.0.0/16", "to": "10.200.0.0/16"},
                ]
            },
            {"unexpected": True},
        ]:
            with self.subTest(change=change), self.assertRaises(mask.MaskError):
                rules(**change)

    def test_addresses_in_urls_and_host_ports(self):
        r = rules()
        self.assertEqual(
            r.text("https://10.10.1.7:443/api"), "https://10.200.1.7:443/api"
        )
        self.assertEqual(r.text("10.10.1.7:389"), "10.200.1.7:389")
        self.assertEqual(r.text("10.10.1.7/32:443"), "10.200.1.7/32:443")

    def test_ipv6(self):
        r = rules(networks=[{"from": "fd12:3456::/32", "to": "fd99:abcd::/32"}])
        self.assertEqual(r.text("[fd12:3456::7]:443"), "[fd99:abcd::7]:443")
        self.assertEqual(r.text("fd12:3456:1234::/48"), "fd99:abcd:1234::/48")

    def test_json_preserves_precision_types_keys_and_policy(self):
        data = '{"name":"alice","address":"10.10.5.7","version":"10.10.1.2","enabled":true,"action":"allow","port":443,"value":123456789.123456789123456789,"sid":"S-1-5-21-123","items":[null,"corp.example"]}'
        result = rules().json(data)
        self.assertIn("123456789.123456789123456789", result)
        value = json.loads(result)
        self.assertEqual(value["action"], "allow")
        self.assertEqual(value["version"], "10.10.1.2")
        self.assertEqual(value["port"], 443)
        self.assertIs(value["enabled"], True)
        self.assertEqual(value["address"], "10.200.5.7")
        self.assertEqual(value["items"], [None, "lab.example"])
        self.assertEqual(value["sid"], "S-1-5-21-123")

    def test_json_duplicate_key_is_not_silently_lost(self):
        with self.assertRaises(mask.MaskError):
            rules().json('{"alice":1,"user-001":2}')
        with self.assertRaises(mask.MaskError):
            rules().json('{"alice":1,"alice":2}')

    def test_embedded_json_escaping_and_newlines(self):
        original = json.dumps(
            {
                "payload": json.dumps({"user": "alice", "host": "corp.example"}),
                "text": 'alice\n"quoted"',
            }
        )
        result = json.loads(rules().json(original))
        self.assertEqual(json.loads(result["payload"])["user"], "user-001")
        self.assertEqual(result["text"], 'user-001\n"quoted"')

    def test_xml_escaping_keeps_policy_well_formed(self):
        import xml.etree.ElementTree as ET

        r = rules(replacements=[{"from": "Alice & Bob", "to": 'Team "A"'}])
        value = r.xml(
            '<rule name="Alice &amp; Bob"><action>allow</action><port>443</port></rule>'
        )
        tree = ET.fromstring(value)
        self.assertEqual(tree.attrib["name"], 'Team "A"')
        self.assertEqual(tree.findtext("action"), "allow")
        self.assertEqual(tree.findtext("port"), "443")
        with self.assertRaises(mask.MaskError):
            r.xml('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')

    def test_array_dimensions_and_nulls(self):
        value = '{"dims":"[0:2]","values":["alice",null,"corp.example"]}'
        self.assertEqual(
            rules().array(value, "text"), '[0:2]={"user-001",NULL,"lab.example"}'
        )

    def test_malformed_collections_and_xml_are_safe_errors(self):
        for change in (
            {"replacements": None},
            {"replacements": {}},
            {"networks": None},
            {"networks": "secret"},
            {"networks": [None]},
        ):
            with self.subTest(change=change), self.assertRaises(mask.MaskError):
                rules(**change)
        with self.assertRaises(mask.MaskError):
            rules().walk('<!DOCTYPE x [<!ENTITY a "alice">]><x>&a;</x>')

    def test_policy_control_values_cannot_be_renamed(self):
        r = rules(replacements=[{"from": "allow", "to": "block"}])
        with self.assertRaises(mask.MaskError):
            r.json('{"action":"allow","enabled":true}')
        with self.assertRaises(mask.MaskError):
            r.xml('<rule action="allow"/>')
        with self.assertRaises(mask.MaskError):
            rules(replacements=[{"from": "enabled", "to": "renamed"}]).json(
                '{"enabled":true}'
            )

    def test_ksc_packed_address_and_opaque_binary(self):
        import base64
        import ipaddress

        packed = base64.b64encode(ipaddress.ip_address("10.10.1.7").packed).decode()
        result = json.loads(
            rules().json(json.dumps({"octets": {"type": "binary", "value": packed}}))
        )
        self.assertEqual(
            str(ipaddress.ip_address(base64.b64decode(result["octets"]["value"]))),
            "10.200.1.7",
        )
        with self.assertRaises(mask.MaskError):
            rules().json('{"unknown":{"type":"binary","value":"YWxpY2U="}}')

    def test_named_credentials_clear_but_unknown_encrypted_content_aborts(self):
        result = json.loads(
            rules().json(
                '{"smtp_password":"plain","openrouter_api_key":"enc:v1:secret","bot_token":"plain"}',
                secrets=True,
            )
        )
        self.assertEqual(
            result, {"smtp_password": "", "openrouter_api_key": "", "bot_token": ""}
        )
        with self.assertRaises(mask.MaskError):
            rules().json('{"document":"enc:v1:opaque"}', secrets=True)

    def test_array_secrets_and_opaque_elements(self):
        value = '{"dims":"[1:1]","values":[{"password":"plain","name":"alice"}]}'
        self.assertNotIn("plain", rules().array(value, "jsonb"))
        for element in ("bytea", "unknown_domain"):
            with self.subTest(element=element), self.assertRaises(mask.MaskError):
                rules().array('{"dims":"[1:1]","values":["YWxpY2U="]}', element)

    def test_required_rule_has_no_values_in_error(self):
        try:
            rules(replacements=[{"from": "sensitive-source", "to": "sensitive-source"}])
        except mask.MaskError as error:
            self.assertNotIn("sensitive-source", str(error))
        else:
            self.fail("identity replacement accepted")

    def test_secret_handling_does_not_disable_policies(self):
        data = '{"enabled":true,"password":"enc:v1:opaque","min_password_length":14,"action":"allow"}'
        result = json.loads(rules().json(data, secrets=True))
        self.assertEqual(result["password"], "")
        self.assertEqual(result["min_password_length"], 14)
        self.assertIs(result["enabled"], True)
        self.assertEqual(result["action"], "allow")


if __name__ == "__main__":
    unittest.main()
