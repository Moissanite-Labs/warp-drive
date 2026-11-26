import sys
sys.path.insert(0,'/tmp/warp-drive-pr12-verify/studies/expedition-gram-cert-upgrades')
import warp_drive_gram_cert_audit as m
h='1'*64; base='b'*64
C=m.HardenedFixedRadixCertificate.create
B=m.HardenedCertificateBounds(
 m.HardenedRationalBound(100,1),m.HardenedRationalBound(100,1),
 m.HardenedRationalBound(100,1),m.HardenedRationalBound(100,1))
actual=C(adapter_id='a1',adapter_sha256=h,base_weights_sha256=base,
 radix_scale=1,frobenius_sq_scaled=16,spectral_norm_sq_scaled=16,
 leakage_energy_scaled=0,max_safety_dot_sq_scaled=0)
stack_hash=m.canonical_stack_composition_digest([('a1',h,1,1)])
forged=C(adapter_id='composed_stack',adapter_sha256=stack_hash,base_weights_sha256=base,
 radix_scale=1,frobenius_sq_scaled=0,spectral_norm_sq_scaled=0,
 leakage_energy_scaled=0,max_safety_dot_sq_scaled=0)
result=m.verify_stack_hardened(
 [(actual,'a1',h,1,1)],B,B,expected_base_weights_sha256=base,
 composed_certificate=forged)
print(result)
