# Independent census: does not import or call the proposing study helper.
import base64, collections, hashlib, json, pathlib, re, struct
p=pathlib.Path('/tmp/warp-drive-pr12-live-layout/round5/repos/qwen-neuron-map-site/4b.html')
raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='cfc229397e1e98d46ccaa270295bcb02114159bfb2ed79cc77f7f6262220f22d'
text=raw.decode('utf-8')
m=re.search(r'const\s+DATA\s*=\s*(\{.*?\});\s*\n',text,re.S)
data=json.loads(m.group(1))
L,W,N=data['layers'],data['width'],data['n']
assert N==L*W
bridge=base64.b64decode(data['structures']['bridges'])
out=[0]*L; inn=[0]*L; backward=same=0
for off in range(0,len(bridge),6):
    writer=int.from_bytes(bridge[off:off+3],'little')
    reader=int.from_bytes(bridge[off+3:off+6],'little')
    assert 0<=writer<N and 0<=reader<N
    wl,rl=divmod(writer,W)[0],divmod(reader,W)[0]
    out[wl]+=1; inn[rl]+=1
    backward+=rl<wl; same+=rl==wl
in_rank=1+sum(v>inn[31] for v in inn)
max_out=max(range(L),key=lambda i:(out[i],-i))
result={
 'source_url':'https://qwen-neuron-map.pages.dev/4b/',
 'source_sha256':hashlib.sha256(raw).hexdigest(),
 'layers':L,'width':W,'neurons':N,'wires':len(bridge)//6,
 'wire_bytes_exact':len(bridge)%6==0,
 'backward_wires':backward,'same_layer_wires':same,
 'L31_outgoing':out[31],'L31_incoming':inn[31],
 'L31_incoming_rank_dense':in_rank,
 'L30_outgoing':out[30],
 'max_outgoing_layer':max_out,'max_outgoing_count':out[max_out],
 'outgoing_by_layer':out,'incoming_by_layer':inn,
}
print(json.dumps(result,indent=2))
