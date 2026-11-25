import json
from datetime import datetime
import streamlit as st
from vajra.scanner import run_assessment

st.set_page_config(page_title="VAJRA-X | Web Security", page_icon="🛡️", layout="wide")

st.markdown(r'''<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root{--bg:#252629;--panel:#303236;--panel2:#292a2d;--border:#44464b;--muted:#a7a8ad;--text:#e5e5e7;--orange:#ff8b36;--blue:#4a9bd6;--red:#ef5963;--yellow:#e5b34c;--green:#65bb83}
.stApp{background:var(--bg);color:var(--text);font-family:Inter,sans-serif}.block-container{padding-top:1rem;padding-bottom:1rem;max-width:100%}
[data-testid="stSidebar"]{background:#202124;border-right:1px solid #414247}.stButton button{border-radius:4px!important;min-height:36px}.stButton button[kind="primary"]{background:var(--orange)!important;color:#171717!important;border:0!important;font-weight:700}
[data-testid="stMetric"]{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:10px}
[data-testid="stMetricLabel"]{color:var(--muted)!important}[data-testid="stMetricValue"]{color:var(--text)!important}
.vx-top{background:#1f2022;border-bottom:1px solid #4a4b50;padding:7px 12px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#c4c5c8}
.vx-brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:1px}.vx-logo{background:#383a3e;border:1px solid #555;border-radius:5px;padding:6px 10px;color:var(--orange)}
.vx-card{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:12px;margin-bottom:8px}.vx-title{font-size:12px;font-weight:700;letter-spacing:.8px;color:#c5c6ca;margin-bottom:10px}.vx-small{font-size:11px;color:var(--muted)}
.vx-tab{padding:6px 11px;border-bottom:2px solid transparent;color:#c7c8cb;font-size:12px}.vx-active{border-bottom:2px solid var(--orange);color:#fff}
.vx-finding{font-family:IBM Plex Mono,monospace;font-size:12px}.vx-pill{display:inline-block;border-radius:3px;padding:2px 7px;font-size:10px;font-weight:700}.vx-high{background:#7d2d35;color:#ffb4b9}.vx-med{background:#73572b;color:#ffe0a1}.vx-low{background:#315f4a;color:#b9f2ce}.vx-info{background:#344e70;color:#c5e2ff}
[data-testid="stDataFrame"]{border:1px solid #484a4f;border-radius:4px}
hr{border-color:#47484c!important}
</style>''', unsafe_allow_html=True)

if 'vx_result' not in st.session_state: st.session_state.vx_result=None
if 'vx_target' not in st.session_state: st.session_state.vx_target=''

with st.sidebar:
    st.markdown('<div class="vx-brand"><div class="vx-logo">VX</div><div>VAJRA-X<div class="vx-small">WEB SECURITY WORKBENCH</div></div></div>',unsafe_allow_html=True)
    st.markdown('---')
    st.markdown('**TARGET & SCOPE**')
    target=st.text_input('Target URL',value=st.session_state.vx_target,placeholder='https://example.com')
    authorized=st.checkbox('Authorized testing only')
    st.caption('Limited, non-destructive checks. Assess only systems you own or have permission to review.')
    run=st.button('▶  Start scan',type='primary',disabled=not(target.strip() and authorized),use_container_width=True)
    st.markdown('---')
    nav=st.radio('WORKSPACE',['Dashboard','Issues','Site map / Assets','Report'],label_visibility='visible')
    st.markdown('---')
    st.markdown('**SCAN MODULES**')
    for mod in ['DNS & IP intelligence','TLS / certificate','HTTP headers','Cookie flags','Technology hints','CT names']:
        st.markdown(f'<div class="vx-small">◈ &nbsp;{mod}</div>',unsafe_allow_html=True)

if run:
    st.session_state.vx_target=target.strip()
    with st.spinner('Collecting passive observations…'):
        try: st.session_state.vx_result=run_assessment(target.strip()); st.toast('Assessment completed')
        except Exception as e: st.error(f'Scan failed: {e}')
result=st.session_state.vx_result

st.markdown('<div class="vx-top"><span>VAJRA-X &nbsp; / &nbsp; Web security assessment</span><span>LOCAL WORKSPACE &nbsp; • &nbsp; v0.1</span></div>',unsafe_allow_html=True)
# target status and quick action row
c1,c2,c3=st.columns([3,1,1])
with c1: st.markdown(f'**Target:** &nbsp; `{(result or {}).get("target",st.session_state.vx_target or "No target selected")}`')
with c2: st.markdown('**Mode:** &nbsp; Passive / limited')
with c3: st.markdown(f'**State:** &nbsp; {"Completed" if result else "Ready"}')
st.markdown('---')

if nav=='Dashboard':
    st.markdown('### Dashboard')
    if result:
        findings=result.get('findings',[]); dns=result.get('dns',{}); summary=result.get('summary',{})
        m1,m2,m3,m4,m5=st.columns(5)
        m1.metric('Observations',len(findings)); m2.metric('Risk triage',summary.get('risk','N/A')); m3.metric('Public IPs',len(dns.get('public_ips',[]))); m4.metric('CT names',len(result.get('subdomains',[]))); m5.metric('HTTP status',result.get('http',{}).get('status_code','N/A'))
        left,right=st.columns([2.3,1])
        with left:
            st.markdown('<div class="vx-card"><div class="vx-title">ISSUE ACTIVITY</div>',unsafe_allow_html=True)
            if findings:
                rows=[]
                for f in findings:
                    rows.append({'Severity':f.get('severity','INFO'),'Issue':f.get('title','Untitled'),'Category':f.get('category',''),'Confidence':f.get('confidence','')})
                st.dataframe(rows,use_container_width=True,hide_index=True)
            else: st.success('No observations from limited checks.')
            st.markdown('</div>',unsafe_allow_html=True)
        with right:
            st.markdown('<div class="vx-card"><div class="vx-title">TARGET SUMMARY</div>',unsafe_allow_html=True)
            st.write('**URL**'); st.code(result.get('target','—'))
            st.write('**TLS verified**', 'Yes' if result.get('tls',{}).get('verified') else 'Unavailable / No')
            st.write('**Technology hints**'); st.write(result.get('technology',[]))
            st.markdown('</div>',unsafe_allow_html=True)
        st.markdown('<div class="vx-card"><div class="vx-title">LATEST SELECTED OBSERVATION</div>',unsafe_allow_html=True)
        if findings:
            f=findings[0]; st.markdown(f'**{f.get("title","Observation")}**'); st.write(f.get('description','')); st.caption(f.get('recommendation',''))
        else: st.caption('No observation details available.')
        st.markdown('</div>',unsafe_allow_html=True)
    else:
        st.info('Enter a target in the left scope panel, confirm authorization, and start the scan.')
        st.markdown('<div class="vx-card"><div class="vx-title">WORKSPACE</div>Scan results will populate the issue table, target summary, and evidence panel.</div>',unsafe_allow_html=True)
elif nav=='Issues':
    st.markdown('### Issues')
    if result:
        findings=result.get('findings',[])
        if findings:
            for i,f in enumerate(findings):
                sev=f.get('severity','INFO').upper(); icon={'HIGH':'🔴','CRITICAL':'🔴','MEDIUM':'🟠','LOW':'🟢'}.get(sev,'🔵')
                with st.expander(f'{icon}  {f.get("title","Observation")}  ·  {sev}',expanded=(i==0)):
                    st.markdown('**Description**'); st.write(f.get('description',''))
                    st.markdown('**Recommendation**'); st.write(f.get('recommendation',''))
                    st.caption(f'Category: {f.get("category","N/A")}  |  Confidence: {f.get("confidence","N/A")}')
        else: st.info('No observations returned.')
    else: st.info('Run a scan first.')
elif nav=='Site map / Assets':
    st.markdown('### Site map / Assets')
    if result:
        tabs=st.tabs(['DNS','TLS','HTTP','Technology','CT names'])
        with tabs[0]: st.json(result.get('dns',{}))
        with tabs[1]: st.json(result.get('tls',{}))
        with tabs[2]: st.json(result.get('http',{}))
        with tabs[3]: st.json(result.get('technology',[]))
        with tabs[4]: st.write(result.get('subdomains',[]))
    else: st.info('Run a scan first.')
elif nav=='Report':
    st.markdown('### Report & export')
    if result:
        st.download_button('⬇ Download JSON report',json.dumps(result,indent=2,ensure_ascii=False),'vajra_x_report.json','application/json')
        st.json(result)
    else: st.info('Run a scan first.')

st.markdown('---')
st.caption('VAJRA-X · Authorized use only · Non-destructive checks · Observations are not proof of exploitable vulnerabilities')
