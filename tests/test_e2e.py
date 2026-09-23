"""End-to-end scenarios over the real adjudication core."""
import base64
import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests import pki_factory as pf
from app.storage import Store
from app.adjudge import adjudicate
from app.package import build_package
from app.certmodel import fp_of
from verify.verify_package import verify_package
import io, zipfile, json

ANY = "2.5.29.32.0"
SIGNED = 1_700_000_000
CUTOFF = 1_701_000_000
RECEIVED = 1_699_000_000


def _sig(leaf_key, artifact=b"artifact"):
    d = hashlib.sha256(artifact).digest()
    s = leaf_key.sign(d, ec.ECDSA(Prehashed(hashes.SHA256())))
    return d, s, "1.2.840.10045.4.3.2"


class Harness:
    def __init__(self, tmp_path):
        self.store = Store(str(tmp_path / "data"))
        self.sid = "es_harness_000000000000000000000001"
        self.store.create_set(self.sid, "create")
        self.rows = []

    def add_cert(self, c, received=RECEIVED):
        d = pf.der(c)
        self.store.put_blob(d)
        self.rows.append({"client_ref": "c" + fp_of(d)[:20],
                          "kind": "certificate", "content_sha256": fp_of(d),
                          "received_at": received})

    def add_rev(self, obj, i, kind="crl", received=RECEIVED):
        d = pf.der(obj)
        self.store.put_blob(d)
        self.rows.append({"client_ref": f"{kind}{i}", "kind": kind,
                          "content_sha256": fp_of(d), "received_at": received})

    def seal(self):
        self.store.add_items(self.sid, self.rows)
        return self.store.seal(self.sid)

    def judge(self, leaf, root_fp, leaf_key=None, policies=(ANY,), signed=SIGNED,
              cutoff=CUTOFF, digest_sig=None):
        d, s, alg = digest_sig or _sig(leaf_key)
        return adjudicate(self.store, self.sid, {
            "artifact_digest": d.hex(), "signature": s.hex(),
            "signature_algorithm": alg, "signed_at": signed,
            "knowledge_cutoff": cutoff,
            "leaf_certificate_sha256": fp_of(pf.der(leaf)),
            "initial_policies": list(policies), "trust_anchors": [root_fp]})


def test_cross_sign_short_revoked_long_valid(tmp_path):
    h = Harness(tmp_path)
    r1k, r2k = pf.gen_key(), pf.gen_key()
    cak, midk, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    r1 = pf.build_cert("R1", None, r1k, r1k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    r2 = pf.build_cert("R2", None, r2k, r2k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       self_signed=True)
    # Same CA subject + key cross-signed by R1 (short) and by Mid under R2.
    x1 = pf.build_cert("Shared CA", r1, cak, r1k, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    mid = pf.build_cert("Mid CA", r2, midk, r2k, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    x2 = pf.build_cert("Shared CA", mid, cak, midk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("codesign", x1, lk, cak,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("codesign.test",))
    # X1 revoked BEFORE signed_at by R1's CRL.
    crl_r1 = pf.build_crl(r1, r1k, [(x1.serial_number, SIGNED - 100_000,
                                     "key_compromise")],
                          last_update=SIGNED - 86400, next_update=SIGNED + 86400,
                          crl_number=5)
    # X2 chain clear.
    crl_mid = pf.build_crl(mid, midk, [], last_update=SIGNED - 86400,
                           next_update=SIGNED + 86400, crl_number=2)
    crl_ca = pf.build_crl(x2, cak, [], last_update=SIGNED - 86400,
                          next_update=SIGNED + 86400, crl_number=2)
    crl_r2 = pf.build_crl(r2, r2k, [], last_update=SIGNED - 86400,
                          next_update=SIGNED + 86400, crl_number=1)
    for c in (r1, r2, x1, x2, mid, leaf):
        h.add_cert(c)
    for i, c in enumerate((crl_r1, crl_mid, crl_ca, crl_r2)):
        h.add_rev(c, i)
    manifest = h.seal()
    # Anchor R1: only path leaf->x1->r1, revoked => REJECTED.
    res1 = h.judge(leaf, fp_of(pf.der(r1)), lk)
    assert res1["verdict"]["status"] == "REJECTED"
    assert res1["verdict"]["failed_rule"] == "REVOCATION"
    # Anchor R2: short branch via R1 impossible; long path accepted.
    res2 = h.judge(leaf, fp_of(pf.der(r2)), lk)
    assert res2["verdict"]["status"] == "VALID", res2["verdict"]
    path = res2["verdict"]["selected_path"]
    assert path == [fp_of(pf.der(leaf)), fp_of(pf.der(x2)),
                    fp_of(pf.der(mid)), fp_of(pf.der(r2))]


def test_bitemporal_cutoff_excludes_late_evidence(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # GOOD CRL possessed by cutoff...
    good = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    # ...and a REVOKED CRL only acquired AFTER the cutoff (forged hindsight):
    # it must NOT change the historical decision.
    late = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 50,
                                  "key_compromise")],
                        last_update=SIGNED + 200, next_update=SIGNED + 900,
                        crl_number=3)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(good, 0); h.add_rev(rcrl, 2)
    h.add_rev(late, 1, received=CUTOFF + 10)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID"
    rr = res["revocation_results"][0]
    assert rr["conclusion"] == "GOOD"
    late_rows = [c for c in rr["considered_evidence"]
                 if c["reason"] == "not_received_by_knowledge_cutoff"]
    assert late_rows and late_rows[0]["eligible"] is False


def test_archival_revoked_response_counts_when_held_by_cutoff(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # OCSP response produced AFTER signed_at but documenting an event BEFORE
    # it; acquired before cutoff => REVOKED at signed_at.
    oc = pf.build_ocsp(leaf, ca, ck, "revoked",
                       this_update=SIGNED + 50_000, next_update=SIGNED + 200_000,
                       revocation_time=SIGNED - 100_000,
                       reason="key_compromise", hash_alg=H.SHA256())
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(oc, 0, kind="ocsp")
    h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "REVOCATION"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    rr = snap[fp_of(pf.der(leaf))]
    assert rr["conclusion"] == "REVOKED"
    assert rr["selected_evidence"]["kind"] == "ocsp"


def test_delta_crl_remove_from_crl(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    base = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                  "certificate_hold")],
                        last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=10)
    delta = pf.build_crl(ca, ck, [(leaf.serial_number, SIGNED - 200_000,
                                   "remove_from_crl")],
                         last_update=SIGNED - 1_000,
                         next_update=SIGNED + 300_000, crl_number=11,
                         delta_of=10)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 300_000,
                        next_update=SIGNED + 300_000, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(base, 0); h.add_rev(delta, 1); h.add_rev(rcrl, 2)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID"
    sel = res["revocation_results"][0]["selected_evidence"]
    assert sel["kind"] == "crl" and sel["delta"] == fp_of(pf.der(delta))


def test_delegated_ocsp_responder(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    h = Harness(tmp_path)
    rk, ck, lk, dk = pf.gen_key(), pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    deleg = pf.build_cert("OCSP Responder", ca, dk, ck,
                          key_usage=("digitalSignature",),
                          eku=("ocspSigning",), policies=[ANY])
    oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                       next_update=SIGNED + 100, responder_key=dk,
                       responder_cert=deleg, hash_alg=H.SHA256())
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf, deleg):
        h.add_cert(c)
    h.add_rev(oc, 0, kind="ocsp"); h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["revocation_results"][0]["selected_evidence"]["kind"] == "ocsp"


def test_rejection_proof_covers_branches(tmp_path):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    # CA without codeSigning EKU propagation: give CA an EKU lacking it,
    # and another CA candidate with a bad signature branch.
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       eku=("1.3.6.1.5.5.7.3.1",))  # serverAuth only
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    proof = res["verdict"]["rejection_proof"]
    assert proof is not None
    edges = {(e["child"], e["parent"]): e["first_failure"]
             for e in proof["edges"]}
    assert (fp_of(pf.der(leaf)), fp_of(pf.der(ca))) in edges
    assert any(f and f["rule"] == "EKU"
               for f in proof["path_level_failures"])


def test_determinism_and_offline_verification(tmp_path):
    from cryptography.hazmat.primitives import hashes as H
    # Build two stores with reversed upload order.
    def build(td):
        h = Harness(td)
        rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
        root = pf.build_cert("R", None, rk, rk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], self_signed=True)
        ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                           key_usage=("keyCertSign", "cRLSign"),
                           policies=[ANY])
        leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY])
        crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                           next_update=SIGNED + 100, crl_number=2)
        rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                            next_update=SIGNED + 100, crl_number=1)
        oc = pf.build_ocsp(leaf, ca, ck, "good", this_update=SIGNED - 100,
                           next_update=SIGNED + 100, hash_alg=H.SHA256())
        return h, (root, ca, leaf), (crl, rcrl, oc), lk

    h1, certs, revs, lk = build(tmp_path / "a")
    fixed_sig = _sig(lk)
    for c in certs:
        h1.add_cert(c)
    for i, r in enumerate(revs[:2]):
        h1.add_rev(r, i)
    h1.add_rev(revs[2], 0, kind="ocsp")
    m1 = h1.seal()
    res1 = h1.judge(certs[2], fp_of(pf.der(certs[0])), digest_sig=fixed_sig)
    pkg1 = build_package(h1.store, res1, m1)

    h2 = Harness(tmp_path / "b")
    for c in reversed(certs):
        h2.add_cert(c)
    h2.add_rev(revs[2], 0, kind="ocsp")
    h2.add_rev(revs[1], 1)
    h2.add_rev(revs[0], 0)
    m2 = h2.seal()
    res2 = h2.judge(certs[2], fp_of(pf.der(certs[0])), digest_sig=fixed_sig)
    assert m1["content_digest"] == m2["content_digest"]
    from app import canonical
    assert canonical.dumps(res1) == canonical.dumps(res2)

    pkg_path = tmp_path / "pkg.zip"
    pkg_path.write_bytes(pkg1)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]

    # Tamper a DER inside the package -> verification must fail.
    zf = zipfile.ZipFile(io.BytesIO(pkg1))
    members = {n: zf.read(n) for n in zf.namelist()}
    der_name = sorted(n for n in members if n.startswith("der/"))[0]
    tampered = bytearray(members[der_name])
    tampered[40] ^= 0xFF
    bad_members = dict(members)
    bad_members[der_name] = bytes(tampered)
    (tmp_path / "bad.zip").write_bytes(_rezip(bad_members))
    assert not verify_package(str(tmp_path / "bad.zip"))["ok"]

    # Tamper a rule conclusion in result.json -> fail.
    result = json.loads(members["result.json"])
    result["verdict"]["status"] = "VALID" if result["verdict"]["status"] != "VALID" else "INVALID"
    from app import canonical as cj
    tr_members = dict(members)
    tr_members["result.json"] = cj.dumps(result)
    (tmp_path / "tampered_result.zip").write_bytes(_rezip(tr_members))
    assert not verify_package(str(tmp_path / "tampered_result.zip"))["ok"]


def _rezip(members: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zo.writestr(info, members[name])
    return out.getvalue()


def test_rejected_package_offline_verifies(tmp_path):
    """A REJECTED adjudication (no valid path) also produces a package whose
    offline recomputation matches byte-for-byte."""
    import zipfile
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       eku=("1.3.6.1.5.5.7.3.1",))  # serverAuth only
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    manifest = h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    pkg = build_package(h.store, res, manifest)
    path = tmp_path / "rejected.zip"
    path.write_bytes(pkg)
    report = verify_package(str(path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_stale_evidence_when_window_expired(tmp_path):
    """A CRL expired before signed_at cannot establish GOOD -> STALE."""
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         self_signed=True)
    ca = pf.build_cert("C", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY])
    leaf = pf.build_cert("L", ca, lk, ck, key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY])
    # CRL validity ended well before signed_at -> stale clearance.
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 1000,
                       next_update=SIGNED - 500, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    snap = {x["certificate"]: x for x in res["revocation_snapshot"]}
    assert snap[fp_of(pf.der(leaf))]["conclusion"] == "STALE"


def _nc_chain_harness(tmp_path, *, intermediate_san, leaf_san,
                      nc_excluded=("bad.example",), nc_permitted=()):
    h = Harness(tmp_path)
    rk, ck, lk = pf.gen_key(), pf.gen_key(), pf.gen_key()
    root = pf.build_cert("NC Root", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_excluded_dns=nc_excluded,
                         nc_permitted_dns=nc_permitted, self_signed=True)
    ca = pf.build_cert(intermediate_san or "NC CA", root, ck, rk, is_ca=True,
                       key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                       san_dns=(intermediate_san,) if intermediate_san else ())
    leaf = pf.build_cert(leaf_san, ca, lk, ck,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=(leaf_san,))
    crl = pf.build_crl(ca, ck, [], last_update=SIGNED - 100,
                       next_update=SIGNED + 100, crl_number=1)
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca, leaf):
        h.add_cert(c)
    h.add_rev(crl, 0)
    h.add_rev(rcrl, 1)
    manifest = h.seal()
    return h, root, ca, leaf, lk, manifest


def test_intermediate_in_excluded_subtree_rejected(tmp_path):
    """Leaf name allowed, but the non-self-issued intermediate's SAN is inside
    the anchor's excluded subtree -> REJECTED / NAME_CONSTRAINTS; the rejected
    package must still recompute byte-for-byte offline."""
    from app.package import build_package
    from verify.verify_package import verify_package

    h, root, ca, leaf, lk, manifest = _nc_chain_harness(
        tmp_path, intermediate_san="ca.bad.example",
        leaf_san="allowed.example")
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "NAME_CONSTRAINTS"
    proof = res["verdict"]["rejection_proof"]
    groups = proof["path_level_failures"]
    assert any(g["rule"] == "NAME_CONSTRAINTS"
               and g["example_path"][1] == fp_of(pf.der(ca))
               for g in groups)

    pkg = build_package(h.store, res, manifest)
    pkg_path = tmp_path / "nc_rejected.zip"
    pkg_path.write_bytes(pkg)
    report = verify_package(str(pkg_path))
    assert report["ok"], [c for c in report["checks"] if not c["ok"]]


def test_intermediate_outside_permitted_subtree_rejected(tmp_path):
    h, root, ca, leaf, lk, _ = _nc_chain_harness(
        tmp_path, intermediate_san="ca.elsewhere.test",
        leaf_san="svc.allowed.example",
        nc_excluded=(), nc_permitted=("allowed.example",))
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "NAME_CONSTRAINTS"


def test_compliant_chain_still_accepted(tmp_path):
    """An intermediate whose SAN sits inside the permitted namespace must not
    be affected by the new pairwise checks."""
    h, root, ca, leaf, lk, _ = _nc_chain_harness(
        tmp_path, intermediate_san="ca.allowed.example",
        leaf_san="app.allowed.example",
        nc_excluded=(), nc_permitted=("allowed.example",))
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]


def test_self_issued_rollover_intermediate_exempt(tmp_path):
    """Root excludes bad.example; the key-rollover self-issued intermediate
    carries a SAN inside that subtree but must remain exempt, so the path is
    VALID."""
    h = Harness(tmp_path)
    rk, k1, k1b, k2, lk = (pf.gen_key() for _ in range(5))
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_excluded_dns=("bad.example",), self_signed=True)
    ca1 = pf.build_cert("Roll CA", root, k1, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                        san_dns=("roll.good.example",))
    # Self-issued RFC 4158 key rollover: same subject DN, new key k1b,
    # signed by the old key k1. The distinct SKI forces path construction
    # through this certificate rather than its same-name/key predecessor.
    ca1b = pf.build_cert("Roll CA", ca1, k1b, k1, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         san_dns=("rollover.bad.example",))
    ca2 = pf.build_cert("Down CA", ca1b, k2, k1b, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"),
                        policies=[ANY], san_dns=("down.good.example",))
    leaf = pf.build_cert("app.good.example", ca2, lk, k2,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("app.good.example",))
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    # The old "Roll CA" key k1 signed ca1b; its GOOD CRL covers ca1b.
    mcrl = pf.build_crl(ca1, k1, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    ncrl = pf.build_crl(ca1b, k1b, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    lcrl = pf.build_crl(ca2, k2, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca1, ca1b, ca2, leaf):
        h.add_cert(c)
    h.add_rev(rcrl, 0); h.add_rev(mcrl, 1)
    h.add_rev(ncrl, 2); h.add_rev(lcrl, 3)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    assert res["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf)), fp_of(pf.der(ca2)), fp_of(pf.der(ca1b)),
        fp_of(pf.der(ca1)), fp_of(pf.der(root))]


def test_non_self_issued_rollover_lookalike_rejected(tmp_path):
    """Same shape as the rollover case but the middle cert has a different
    subject: it is not self-issued and therefore loses the exemption."""
    h = Harness(tmp_path)
    rk, k1, km, k2, lk = (pf.gen_key() for _ in range(5))
    root = pf.build_cert("R", None, rk, rk, is_ca=True,
                         key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                         nc_excluded_dns=("bad.example",), self_signed=True)
    ca1 = pf.build_cert("Roll CA", root, k1, rk, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                        san_dns=("roll.good.example",))
    mid = pf.build_cert("mid.bad.example", ca1, km, k1, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"), policies=[ANY],
                        san_dns=("mid.bad.example",))
    ca2 = pf.build_cert("Down CA", mid, k2, km, is_ca=True,
                        key_usage=("keyCertSign", "cRLSign"),
                        policies=[ANY], san_dns=("down.good.example",))
    leaf = pf.build_cert("app.good.example", ca2, lk, k2,
                         key_usage=("digitalSignature",),
                         eku=("codeSigning",), policies=[ANY],
                         san_dns=("app.good.example",))
    rcrl = pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    mcrl = pf.build_crl(ca1, k1, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    mcrl2 = pf.build_crl(mid, km, [], last_update=SIGNED - 100,
                         next_update=SIGNED + 100, crl_number=1)
    lcrl = pf.build_crl(ca2, k2, [], last_update=SIGNED - 100,
                        next_update=SIGNED + 100, crl_number=1)
    for c in (root, ca1, mid, ca2, leaf):
        h.add_cert(c)
    h.add_rev(rcrl, 0); h.add_rev(mcrl, 1)
    h.add_rev(mcrl2, 2); h.add_rev(lcrl, 3)
    h.seal()
    res = h.judge(leaf, fp_of(pf.der(root)), lk)
    assert res["verdict"]["status"] == "REJECTED"
    assert res["verdict"]["failed_rule"] == "NAME_CONSTRAINTS"


def test_cross_signed_branches_adjudicated_independently(tmp_path):
    """The shared subject/key CA is cross-signed by a superior whose SAN is in
    the anchor's excluded subtree and by a compliant superior. The two
    equivalent branches must conclude independently: both present -> the
    compliant path wins (VALID); bad branch alone -> REJECTED."""
    def build_store(td, *, include_good_superior):
        h = Harness(td)
        rk, xk, badk, goodk, lk = (pf.gen_key() for _ in range(5))
        root = pf.build_cert("R", None, rk, rk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY],
                             nc_excluded_dns=("bad.example",),
                             self_signed=True)
        cbad = pf.build_cert("ca.bad.example", root, badk, rk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], san_dns=("ca.bad.example",))
        cgood = pf.build_cert("ca.good.example", root, goodk, rk, is_ca=True,
                              key_usage=("keyCertSign", "cRLSign"),
                              policies=[ANY], san_dns=("ca.good.example",))
        xbad = pf.build_cert("Shared CA", cbad, xk, badk, is_ca=True,
                             key_usage=("keyCertSign", "cRLSign"),
                             policies=[ANY], san_dns=("x.good.example",))
        certs = [root, cbad, cgood, xbad]
        sup_keys = [(cbad, badk)]
        xgood = None
        if include_good_superior:
            xgood = pf.build_cert("Shared CA", cgood, xk, goodk, is_ca=True,
                                  key_usage=("keyCertSign", "cRLSign"),
                                  policies=[ANY], san_dns=("x.good.example",))
            certs.append(xgood)
            sup_keys.append((cgood, goodk))
        leaf = pf.build_cert("app.good.example", xbad, lk, xk,
                             key_usage=("digitalSignature",),
                             eku=("codeSigning",), policies=[ANY],
                             san_dns=("app.good.example",))
        certs.append(leaf)
        for c in certs:
            h.add_cert(c)
        for i, (sup, supk) in enumerate(sup_keys):
            h.add_rev(pf.build_crl(sup, supk, [], last_update=SIGNED - 100,
                                   next_update=SIGNED + 100, crl_number=1),
                      f"sup{i}")
        h.add_rev(pf.build_crl(xbad, xk, [], last_update=SIGNED - 100,
                               next_update=SIGNED + 100, crl_number=1), "x")
        h.add_rev(pf.build_crl(root, rk, [], last_update=SIGNED - 100,
                               next_update=SIGNED + 100, crl_number=1), "r")
        h.seal()
        return h, root, leaf, lk, xgood, cgood

    hb, root_b, leaf_b, lkb, _, _ = build_store(
        tmp_path / "bad", include_good_superior=False)
    res_bad = hb.judge(leaf_b, fp_of(pf.der(root_b)), lkb)
    assert res_bad["verdict"]["status"] == "REJECTED"
    assert res_bad["verdict"]["failed_rule"] == "NAME_CONSTRAINTS"

    hg, root_g, leaf_g, lkg, xgood, cgood = build_store(
        tmp_path / "both", include_good_superior=True)
    res = hg.judge(leaf_g, fp_of(pf.der(root_g)), lkg)
    assert res["verdict"]["status"] == "VALID", res["verdict"]
    # The winning path runs through the compliant cross-sign only.
    assert res["verdict"]["selected_path"] == [
        fp_of(pf.der(leaf_g)), fp_of(pf.der(xgood)),
        fp_of(pf.der(cgood)), fp_of(pf.der(root_g))]


