"""Unit tests for chain-level gates: pathLen, name constraints, EKU,
RFC 5280 policy processing (mappings, anyPolicy inhibition)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app import chain
from app.certmodel import parse_certificate

ANY = "2.5.29.32.0"
P1 = "1.2.3.4.5.1"
P2 = "1.2.3.4.5.2"
T = 1_700_000_000


def _p(derb):
    return parse_certificate(derb)


def _chain3(root_b, ca_b, leaf_b):
    return [_p(leaf_b), _p(ca_b), _p(root_b)]


def _chain4(root_b, ca1_b, ca2_b, leaf_b):
    return [_p(leaf_b), _p(ca2_b), _p(ca1_b), _p(root_b)]


def test_pathlen_violation():
    rk, k1, k2, lk = [pf.gen_key() for _ in range(4)]
    root = pf.build_cert("R", None, rk, rk, is_ca=True, path_len=0,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca1 = pf.build_cert("C1", root, k1, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    ca2 = pf.build_cert("C2", ca1, k2, k1, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca2, lk, k2, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    p = _chain4(pf.der(root), pf.der(ca1), pf.der(ca2), pf.der(leaf))
    ok, d = chain.check_path_len(p)
    assert not ok and d["rule"] == "PATH_LEN"


def test_dns_name_constraint_permitted_and_excluded():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_permitted_dns=("example.com",), self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_ok = pf.build_cert("L1", ca, lk, ck, key_usage=("digitalSignature",),
                            eku=("codeSigning",), policies=[ANY],
                            san_dns=("app.example.com",))
    leaf_bad = pf.build_cert("L2", ca, pf.gen_key(), ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY],
                             san_dns=("evil.test",))
    assert chain.check_name_constraints(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_ok)))[0]
    ok, d = chain.check_name_constraints(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_bad)))
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"

    # excluded subtree
    root2 = pf.build_cert("R2", None, rk, rk, is_ca=True,
                          key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                          nc_excluded_dns=("bad.example.com",), self_signed=True)
    leaf_ex = pf.build_cert("L3", ca, pf.gen_key(), ck,
                            key_usage=("digitalSignature",),
                            eku=("codeSigning",), policies=[ANY],
                            san_dns=("x.bad.example.com",))
    # root2 signed its own CA chain variant: rebuild ca under root2
    ca2 = pf.build_cert("C2b", root2, ck, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_ex2 = pf.build_cert("L3b", ca2, pf.gen_key(), ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY],
                             san_dns=("x.bad.example.com",))
    ok, d = chain.check_name_constraints(_chain3(pf.der(root2), pf.der(ca2), pf.der(leaf_ex2)))
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"


def test_uri_name_constraint():
    assert chain.uri_in_subtree("https://a.example.com/x", "example.com")
    assert chain.uri_in_subtree("https://example.com:8443/", "example.com")
    assert not chain.uri_in_subtree("https://example.com.evil.test/", "example.com")


def _ca_chain(root_kw, ca_kw, leaf_kw, *, ca_san_subject="C", rollover=False):
    """Build [leaf, (rollover,) ca, root] with GOOD-shaped extensions."""
    rk, ck, ck2, lk = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True, **root_kw)
    ca = pf.build_cert(ca_san_subject, root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       **ca_kw)
    issuer, issuer_key = ca, ck
    if rollover:
        # Self-issued (issuer DN == subject DN, new key) key-rollover cert.
        roll = pf.build_cert(ca_san_subject, ca, ck2, ck, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], **leaf_kw.pop("roll_kw", {}))
        issuer, issuer_key = roll, ck2
    else:
        roll = None
    leaf = pf.build_cert("L", issuer, lk, issuer_key,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY], **leaf_kw)
    if roll is not None:
        return [_p(pf.der(leaf)), _p(pf.der(roll)),
                _p(pf.der(ca)), _p(pf.der(root))]
    return _chain3(pf.der(root), pf.der(ca), pf.der(leaf))


def test_intermediate_san_matches_excluded_subtree():
    # The leaf name is fine; the *intermediate* CA's SAN is inside the
    # root's excluded subtree -> the whole path must be rejected.
    p = _ca_chain(
        root_kw={"nc_excluded_dns": ("bad.example",)},
        ca_kw={"san_dns": ("ca.bad.example",)},
        leaf_kw={"san_dns": ("allowed.example",)})
    ok, d = chain.check_name_constraints(p)
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"
    assert d["at"] == p[2].fingerprint          # constraining root
    assert d["name_at"] == p[1].fingerprint     # offending intermediate
    assert d["kind"] == "dns_excluded"
    assert d["name"] == "ca.bad.example"


def test_intermediate_san_outside_permitted_subtree():
    p = _ca_chain(
        root_kw={"nc_permitted_dns": ("allowed.example",)},
        ca_kw={"san_dns": ("ca.elsewhere.test",)},
        leaf_kw={"san_dns": ("leaf.allowed.example",)})
    ok, d = chain.check_name_constraints(p)
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"
    assert d["at"] == p[2].fingerprint and d["name_at"] == p[1].fingerprint
    assert d["kind"] == "dns_not_permitted"


def test_intermediate_uri_san_matches_excluded_subtree():
    p = _ca_chain(
        root_kw={"nc_excluded_uri": ("bad.example",)},
        ca_kw={"san_uri": ("https://ca.bad.example/cert",)},
        leaf_kw={"san_uri": ("https://allowed.example/app",)})
    ok, d = chain.check_name_constraints(p)
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"
    assert d["name_at"] == p[1].fingerprint and d["kind"] == "uri_excluded"


def test_intermediate_without_san_not_constrained_by_permitted():
    # RFC 5280: constraints apply to names present; a CA cert with no SAN
    # has no DNS/URI names and cannot fail a permitted-subtree constraint.
    p = _ca_chain(
        root_kw={"nc_permitted_dns": ("example.com",)},
        ca_kw={},
        leaf_kw={"san_dns": ("app.example.com",)})
    assert chain.check_name_constraints(p)[0]


def test_exclusion_takes_priority_over_permitted():
    # ca.bad.example is in both the permitted "example" subtree and the
    # excluded "bad.example" subtree: exclusion must win.
    p = _ca_chain(
        root_kw={"nc_permitted_dns": ("example",),
                 "nc_excluded_dns": ("bad.example",)},
        ca_kw={"san_dns": ("ca.bad.example",)},
        leaf_kw={"san_dns": ("x.example",)})
    ok, d = chain.check_name_constraints(p)
    assert not ok and d["kind"] == "dns_excluded"


def test_self_issued_rollover_intermediate_exempt():
    # A self-issued intermediate in a non-final position keeps the existing
    # exemption even though its SAN sits in an excluded subtree; the leaf
    # name is still constrained.
    p = _ca_chain(
        root_kw={"nc_excluded_dns": ("bad.example",)},
        ca_kw={"san_dns": ("ca.allowed.example",)},
        leaf_kw={"san_dns": ("leaf.allowed.example",),
                 "roll_kw": {"san_dns": ("ca.bad.example",)}},
        ca_san_subject="Shared CA", rollover=True)
    assert chain.check_name_constraints(p)[0]
    # Same shape, but the leaf itself hits the exclusion -> rejected.
    p2 = _ca_chain(
        root_kw={"nc_excluded_dns": ("bad.example",)},
        ca_kw={"san_dns": ("ca.allowed.example",)},
        leaf_kw={"san_dns": ("leaf.bad.example",),
                 "roll_kw": {"san_dns": ("ca.bad.example",)}},
        ca_san_subject="Shared CA", rollover=True)
    ok, d = chain.check_name_constraints(p2)
    assert not ok and d["kind"] == "dns_excluded"
    assert d["name_at"] == p2[0].fingerprint     # the leaf, not the rollover


def test_leaf_cn_fallback_still_applies():
    # No SAN on the leaf: subject CN matched as a DNS name.
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_permitted_dns=("example.com",), self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_ok = pf.build_cert("app.example.com", ca, lk, ck,
                            key_usage=("digitalSignature",),
                            eku=("codeSigning",), policies=[ANY])
    leaf_bad = pf.build_cert("evil.test", ca, pf.gen_key(), ck,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY])
    assert chain.check_name_constraints(
        _chain3(pf.der(root), pf.der(ca), pf.der(leaf_ok)))[0]
    ok, d = chain.check_name_constraints(
        _chain3(pf.der(root), pf.der(ca), pf.der(leaf_bad)))
    assert not ok and d["rule"] == "NAME_CONSTRAINTS"
    assert d["name_at"] == _p(pf.der(leaf_bad)).fingerprint


def test_eku_code_signing_required():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf_no_eku = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                                policies=[ANY])
    ok, d = chain.check_eku(_chain3(pf.der(root), pf.der(ca), pf.der(leaf_no_eku)))
    assert not ok and d["rule"] == "EKU"


def test_policy_simple_intersection():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P1])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert ok
    ok, d, _ = chain.process_policies(p, frozenset({P2}))
    assert not ok and d["reason"] == "no_acceptable_policy"


def test_policy_mapping_allowed():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    # CA maps its issuer-domain P1 to subject-domain P2 for the leaf.
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1],
                       policy_mappings=((P1, P2),))
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P2])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert ok, d


def test_policy_mapping_inhibited():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         inhibit_policy_mapping=0, self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[P1],
                       policy_mappings=((P1, P2),))
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[P2])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert not ok and d["reason"] == "policyMapping_inhibited"


def test_any_policy_inhibited():
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    # Root inhibits anyPolicy after 1 cert: CA may still use ANY, leaf must not.
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         inhibit_any_policy=1, self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    p = _chain3(pf.der(root), pf.der(ca), pf.der(leaf))
    ok, d, _ = chain.process_policies(p, frozenset({P1}))
    assert not ok
