(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let projects = [], uploaded = null, current = null, job = null;
  const names = {single_agent_reconciliation:'AI Agent',fixed_order:'Thứ tự cố định',cheapest_source:'Nguồn ít byte',unresolved_priority:'Ưu tiên phần chưa rõ'};
  async function api(path, options) {
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Không tải được dữ liệu.');
    return data;
  }
  const el = (tag, text, cls) => { const node=document.createElement(tag); if(text!==undefined)node.textContent=text; if(cls)node.className=cls; return node; };
  function row(parent, label, title, detail) {
    const node=el('div',undefined,'row'), body=el('div');
    node.append(el('span',label,'tag '+label)); body.append(el('p',title));
    if(detail)body.append(el('small',detail)); node.append(body); parent.append(node);
  }
  function scanners() {
    const project=projects.find(p=>p.name===$('project').value); $('scanner').replaceChildren();
    for(const name of project?.scanners||[]) {const option=el('option',name);option.value=name;$('scanner').append(option);}
  }
  async function history() {
    const rows=await api('/api/agent/runs'); $('history').replaceChildren();
    if(!rows.length)$('history').append(el('p','Chưa có phiên khôi phục.','hint'));
    for(const data of rows){const button=el('button',`${names[data.policy]||data.policy} · ${data.status}`,'item');button.append(el('span',`${data.id} · ${data.budget===null?'không giới hạn':data.budget+' lượt'}`));button.addEventListener('click',()=>load(data.id));$('history').append(button);}
  }
  function draw(id,graph,added,removed) {
    const svg=$(id), ns='http://www.w3.org/2000/svg';svg.replaceChildren();svg.setAttribute('viewBox','0 0 520 400');
    const mk=(tag,attrs)=>{const node=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))node.setAttribute(k,v);return node;};
    const defs=mk('defs',{}),marker=mk('marker',{id:`arrow-${id}`,viewBox:'0 0 10 10',refX:18,refY:5,markerWidth:5,markerHeight:5,orient:'auto'});marker.append(mk('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#8baba0'}));defs.append(marker);svg.append(defs);
    const positions=new Map(), count=graph.nodes.length, columns=Math.max(2,Math.ceil(Math.sqrt(count*1.35))), rows=Math.max(1,Math.ceil(count/columns));
    graph.nodes.forEach((node,index)=>positions.set(node.id,{x:35+(index%columns)*(450/Math.max(1,columns-1)),y:35+Math.floor(index/columns)*(325/Math.max(1,rows-1))}));
    for(const [source,target] of graph.edges){const a=positions.get(source),b=positions.get(target);if(!a||!b)continue;const key=JSON.stringify([source,target]);const cls=added.has(key)?' added':removed.has(key)?' removed':'';svg.append(mk('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,class:'edge'+cls,'marker-end':`url(#arrow-${id})`}));}
    for(const node of graph.nodes){const p=positions.get(node.id),group=mk('g',{class:'node',tabindex:0,role:'button','aria-label':node.name,transform:`translate(${p.x},${p.y})`});group.append(mk('circle',{r:10}));const text=mk('text',{y:23,'text-anchor':'middle'});text.textContent=node.name.length>13?node.name.slice(0,12)+'…':node.name;group.append(text);const title=mk('title',{});title.textContent=node.purl||node.name;group.append(title);const select=()=>{$('node-detail').textContent=`${node.name} · ${node.purl||'Định danh chưa rõ'} · ref: ${node.id}`;};group.addEventListener('click',select);group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' ')select();});svg.append(group);}
  }
  function renderGraphs() {
    if(!current)return;
    const all=$('graph-scope').value==='all';
    const before=all?current.observed_graph_all:current.observed_graph,after=all?current.candidate_graph_all:current.candidate_graph;
    draw('before-graph',before,new Set(),new Set(current.removed_edges.map(e=>JSON.stringify(e))));
    draw('after-graph',after,new Set(current.added_edges.map(e=>JSON.stringify(e))),new Set());
    $('before-count').textContent=`Hiển thị ${before.displayed_nodes}/${before.total_nodes} · tổng ${before.overall_nodes} package trong SBOM`;
    $('after-count').textContent=`Hiển thị ${after.displayed_nodes}/${after.total_nodes} · tổng ${after.overall_nodes} package trong SBOM`;
  }
  async function load(id) {
    try{
      current=await api('/api/agent/details?run='+encodeURIComponent(id));const data=current;
      $('empty').hidden=true;$('result').hidden=false;$('run-id').textContent=id;$('result-title').textContent=names[data.policy]||data.policy;
      $('result-target').textContent='Ngữ cảnh target: '+((data.target_purls||[]).join(', ')||'Chưa khai báo root');
      $('added').textContent=data.added_edges.length;$('removed').textContent=data.removed_edges.length;$('unknown').textContent=data.assessment_counts.UNKNOWN||0;$('reads').textContent=`${data.acquired_sources} / ${data.attempts}`;
      $('validation').textContent=`${data.validation.valid?'Định dạng hợp lệ':'Output cần kiểm tra định dạng'} · ${data.status} · ${data.llm_api_calls} lần gọi LLM. ${data.scope}`;
      $('validation').className='notice'+(data.validation.valid?'':' error');$('download').disabled=!data.validation.valid;
      renderGraphs();
      $('change-list').replaceChildren();const labels=new Map([...data.observed_graph.nodes,...data.candidate_graph.nodes].map(n=>[n.id,n.name]));
      for(const proposal of data.proposals)row($('change-list'),'SUPPORTED',proposal.operation==='add_dependency'?`${labels.get(proposal.subject)||proposal.subject} → ${labels.get(proposal.value)||proposal.value}`:`Bổ sung component ${proposal.value.name}`,(proposal.evidence_ids||[]).join(' · '));
      for(const assessment of data.assessments.filter(a=>a.status!=='SUPPORTED').slice(0,100))row($('change-list'),assessment.status,`${labels.get(assessment.source_ref)||assessment.source_ref} → ${labels.get(assessment.target_ref)||assessment.target_ref}`,assessment.reason);
      if(!$('change-list').children.length)$('change-list').append(el('p','Chưa có thay đổi hoặc đánh giá bổ sung.','hint'));
      $('source-list').replaceChildren();$('source-content').textContent='Chọn một nguồn đã được thu thập.';
      for(const source of data.source_ids){const button=el('button',source.slice(0,12)+'…','source-button');button.addEventListener('click',async()=>{try{const e=await api('/api/agent/evidence?run='+encodeURIComponent(id)+'&source='+source);$('source-content').textContent=`SHA-256: ${e.sha256}\n${e.truncated?'Hiển thị phần đầu nội dung.\n':''}\n${e.content}`;}catch(e){$('source-content').textContent=e.message;}});$('source-list').append(button);}
      $('risk-list').replaceChildren();const risks=(data.risk?.records||[]).filter(r=>r.advisory_id);
      for(const risk of risks){const entry=el('div',undefined,'row'),body=el('div'),link=el('a',risk.advisory_id,'risk-link');link.href='https://osv.dev/vulnerability/'+encodeURIComponent(risk.advisory_id);link.target='_blank';link.rel='noopener noreferrer';body.append(link,el('p',risk.purl),el('small',`${risk.path_status} · cần điều tra · exploitability UNKNOWN`));entry.append(el('span','L'+risk.evidence_level,'tag'),body);$('risk-list').append(entry);}
      if(!risks.length)$('risk-list').append(el('p','Không có advisory khớp trong dữ liệu hiện có. Điều này không chứng minh phần mềm an toàn.','hint'));
      $('risk-note').textContent=data.risk?`${data.risk.records.filter(r=>r.advisory_lookup==='UNKNOWN_NOT_QUERIED').length} package chưa có truy vấn trong snapshot. Artifact triển khai chưa được xác minh.`:'Chưa có snapshot advisory cho phiên này.';
      $('trace-list').replaceChildren();for(const [index,trace] of data.trace.entries())row($('trace-list'),trace.status,`${index+1}. ${trace.tool}`,`${trace.attempts}${data.budget===null?' (không giới hạn)':'/'+data.budget} lượt thử · ${trace.bytes_read} byte${trace.reason?' · '+trace.reason:''}`);
    }catch(e){$('job-status').textContent=e.message;}
  }
  async function poll() {
    if(!job)return;
    try{const value=await api('/api/agent/job?id='+job);$('job-status').textContent=`${value.status} · ${value.elapsed_seconds}s · ${value.progress?.source_reads||0} nguồn đã đọc${value.progress?.turn?' · lượt model '+value.progress.turn:''}`;
      if(['COMPLETE','PARTIAL','ERROR'].includes(value.status)){job=null;$('run').disabled=false;await history();if(value.status!=='ERROR')await load(value.run_id);else $('job-status').textContent='Phiên gặp lỗi: '+value.error;return;}
    }catch(e){$('job-status').textContent=e.message;}setTimeout(poll,1500);
  }
  $('run').addEventListener('click',async()=>{try{$('run').disabled=true;const body={project:$('project').value,scanner:$('scanner').value,policy:$('policy').value,budget:$('budget').value==='unlimited'?null:Number($('budget').value),streaming:true};if(uploaded)body.document=uploaded;const value=await api('/api/agent/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});job=value.job_id;poll();}catch(e){$('job-status').textContent=e.message;$('run').disabled=false;}});
  $('project').addEventListener('change',scanners);$('refresh').addEventListener('click',history);
  $('graph-scope').addEventListener('change',renderGraphs);
  $('upload').addEventListener('change',async event=>{try{const file=event.target.files[0];if(!file){uploaded=null;return;}if(file.size>1500000)throw new Error('File JSON tối đa 1,5 MB.');uploaded=JSON.parse(await file.text());$('upload-name').textContent=file.name+' · đối chiếu với target đang chọn';}catch(e){uploaded=null;$('upload-name').textContent=e.message;}});
  document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b===button));document.querySelectorAll('.tab-content').forEach(p=>p.hidden=p.id!==button.dataset.tab);}));
  $('download').addEventListener('click',()=>{if(!current?.validation.valid)return;const url=URL.createObjectURL(new Blob([JSON.stringify(current.document,null,2)],{type:'application/json'}));const link=el('a');link.href=url;link.download=current.id+'-candidate.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  let pilot=null;
  function renderPilot() {
    if(!pilot)return;
    const summary=pilot.summary;
    const selected=summary.cases.find(c=>c.version===$('pilot-version').value&&c.profile===$('pilot-profile').value&&c.input===$('pilot-input').value);
    if(!selected)return;
    const path=selected.static.constructor_path;
    $('pilot-static-status').textContent=`Hàm liên quan bản vá: ${path.status} · analyzer ${selected.static.status}`;
    $('pilot-static-path').replaceChildren();
    if(path.symbols)path.symbols.forEach((symbol,index)=>{const loc=path.locations[index];$('pilot-static-path').append(el('li',symbol+(loc?` (${loc.file}:${loc.line})`:'')));});
    else $('pilot-static-path').append(el('li','Không quan sát được đường tới constructor; trạng thái UNKNOWN.'));
    const apiPath=selected.static.api_path;
    $('pilot-api-path').textContent='Đường tới API: '+(apiPath.symbols?apiPath.symbols.join(' → '):'UNKNOWN')+'. Một đường tới API chưa đủ chứng minh lỗi.';
    const witnessed=selected.fault_witness==='BENIGN_FAULT_WITNESSED';
    $('pilot-witness').textContent=witnessed?'Đã quan sát cơ chế lỗi vô hại với đầu vào này.':selected.fault_witness==='UNKNOWN'?'UNKNOWN · Chưa đủ bằng chứng để đánh giá.':'NOT_OBSERVED · Chưa quan sát lỗi với đầu vào này.';
    $('pilot-runtime-result').textContent='Kết quả: '+(selected.error?selected.error.type+': '+selected.error.message:selected.result_repr)+` · Hàm constructor tại runtime: ${selected.dynamic_function_entry.status}`;
    const control=summary.cases.find(c=>c.version==='5.4.1'&&c.profile===selected.profile&&c.input===selected.input);
    $('pilot-fixed-control').textContent=`Cùng ứng dụng/đầu vào trên bản vá 5.4.1: ${control.fault_witness} · ${control.error?.type||control.result_repr}. Trạng thái sản phẩm vẫn cần điều tra.`;
    $('pilot-audit').textContent=JSON.stringify({input_sha256:selected.input_sha256,audit_events:selected.audit_events},null,2);
    $('pilot-provenance').textContent=`${pilot.run} · CVE-2020-14343 · ${summary.runtime_case_count} ca runtime / ${summary.static_case_count} ca tĩnh · Python ${selected.environment?.python||'UNKNOWN'} · source-tree execution · summary SHA-256: ${pilot.summary_sha256}`;
  }
  ['pilot-version','pilot-profile','pilot-input'].forEach(id=>$(id).addEventListener('change',renderPilot));
  $('pilot-download').addEventListener('click',()=>{if(!pilot)return;const url=URL.createObjectURL(new Blob([JSON.stringify(pilot,null,2)],{type:'application/json'}));const link=el('a');link.href=url;link.download=pilot.run+'-evidence.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  (async()=>{try{const data=await api('/api/agent/reachability');$('pilot-scope').textContent=data.scope||data.reason;if(data.status!=='VERIFIED')return;pilot=data;const labels={direct:'FullLoader trực tiếp',wrapper:'Wrapper / alias',safe:'SafeLoader',cooccurrence:'Chỉ cùng xuất hiện',guard:'Guard chặn tag Python',ordinary:'YAML thông thường',arithmetic:'Payload số học 40 + 2'};for(const [id,key] of [['pilot-version','version'],['pilot-profile','profile'],['pilot-input','input']]){for(const value of new Set(data.summary.cases.map(c=>c[key]))){const option=el('option',labels[value]||value);option.value=value;$(id).append(option);}}$('pilot-input').value='arithmetic';$('pilot-result').hidden=false;renderPilot();}catch(e){$('pilot-scope').textContent='Chưa xác minh được artifact pilot: '+e.message;}})();
  (async()=>{try{const settings=await api('/api/agent/settings');$('gateway').textContent=settings.gateway_configured?'● Gateway đã cấu hình':'○ Chưa cấu hình gateway';projects=await api('/api/agent/projects');$('project').replaceChildren();for(const project of projects){const option=el('option',`${project.name} @ ${project.version}`);option.value=project.name;$('project').append(option);}if(projects.some(p=>p.name==='requests'))$('project').value='requests';scanners();await history();}catch(e){$('job-status').textContent=e.message;}})();
})();
