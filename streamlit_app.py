"""
OLT Finder - Streamlit web app
------------------------------
Run:   streamlit run streamlit_app.py
Keep olt_app.py in the same folder: all OLT logic (Telnet/SSH, parsers, safety rules,
Gemini, Today Losi) is reused from it. Only the tkinter screen is replaced by this web UI.
Needs:  pip install streamlit paramiko
"""
import os
import re
import time
from datetime import date, datetime

import streamlit as st

import olt_app as B

st.set_page_config(page_title="OLT ONU Finder", page_icon="📡", layout="wide")


@st.cache_resource
def _patches():
    B.install_patches()          # cleaner output, Huawei fixes (same as the desktop app)
    return True


_patches()

MODES = {
    "ONU SN": "sn",
    "Router MAC": "mac",
    "PON + ONU (manual)": "onu",
    "PON status": "pon",
    "PON monitor": "monitor",
}
S = st.session_state


# ------------------------------------------------------------------ state / settings
def init_state():
    if "init" in S:
        return
    S.init = True
    S.settings = B.load_settings()
    S.olts = B.load_olts()
    if not S.olts:
        S.olts = B.seed_olts()
    if B.apply_ip_fixes(S.olts):
        B.save_olts(S.olts)
    S.result = None
    S.snap = {}
    S.losi_raw = None
    S.losi_time = None
    S.ai = {}
    last = set(S.settings.get("selected", []))
    for o in S.olts:
        S[f"sel::{B.olt_key(o)}"] = B.olt_key(o) in last


init_state()


def secret(name, default=""):
    try:
        return st.secrets.get(name, default)
    except Exception:
        return default


def selected_olts():
    return [o for o in S.olts if S.get(f"sel::{B.olt_key(o)}")]


def set_all(val):
    for o in S.olts:
        S[f"sel::{B.olt_key(o)}"] = val


def creds():
    user = (S.get("user") or S.settings.get("user") or B.DEFAULT_USER).strip()
    pw = S.get("pw") or os.environ.get("OLT_PASSWORD", "") or secret("OLT_PASSWORD")
    return user, pw


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("📡 OLT ONU Finder")
    st.text_input("Username", value=S.settings.get("user", B.DEFAULT_USER), key="user")
    st.text_input("Password", type="password", key="pw",
                  help="Kept only in this browser session. Never saved to disk.")
    st.text_input("Gemini API key (for AI Analyze)", type="password", key="gem_key",
                  help="Or set GEMINI_API_KEY / st.secrets. Optional.")
    st.divider()
    c1, c2 = st.columns(2)
    c1.button("Select all", on_click=set_all, args=(True,), width="stretch")
    c2.button("Clear", on_click=set_all, args=(False,), width="stretch")
    groups = {}
    for o in S.olts:
        groups.setdefault(o.get("group", ""), []).append(o)
    for g, items in groups.items():
        n_sel = sum(1 for o in items if S.get(f"sel::{B.olt_key(o)}"))
        with st.expander(f"{g or 'No group'}  ({n_sel}/{len(items)})"):
            for o in items:
                st.checkbox(f"{o['name']}  ·  {o.get('vendor', '')}", key=f"sel::{B.olt_key(o)}")
    st.caption(f"{len(selected_olts())} OLT selected")

tab_find, tab_losi, tab_list = st.tabs(["🔎 Find / Monitor", "🔴 Today Losi", "⚙️ OLT list"])


# ------------------------------------------------------------------ input parsing
def parse_keys(mode, text, pon_title):
    keys = []
    for line in text.splitlines():
        line = B.olt_clean(line)
        if not line:
            continue
        if mode == "sn" and not B.SN_RE.match(line):
            raise ValueError(f"This SN is not valid: {line!r} (letters/numbers and : - _ . only)")
        if mode in ("pon", "monitor") and not re.fullmatch(r"(?i)(?:gpon\s*)?\d+(?:\s*/\s*\d+){0,2}", line):
            raise ValueError(f"This PON is not valid: {line!r} (for example 7, 0/7, or 0/1/7 for Huawei)")
        if mode == "onu" and not re.fullmatch(
                r"(?i)(?:gpon\s*)?\d+(?:\s*/\s*\d+){0,2}\s*(?:onu|ont)?\s*[\s:,]\s*\d+", line):
            raise ValueError(f"This is not valid: {line!r} (BDCOM: 7 48 or 0/7:48   Huawei: 0/1/7 12 or 0/1/7:12)")
        if mode == "mac" and len(B.hex12(line)) != 12:
            raise ValueError(f"This MAC is not valid: {line!r} (it needs 12 hex digits)")
        if line not in keys:
            keys.append(line)
    return keys


def summary_block(done, skipped, errors, n_olts):
    st.caption(f"{n_olts} OLT selected, logged in to {done}.")
    for k, v in skipped.items():
        st.warning(f"Skipped **{k}**: {v}")
    for k, v in errors.items():
        st.error(f"**{k}**: {v}")


# ------------------------------------------------------------------ hit rendering
def render_actions(h, hid):
    user, pw = creds()
    cmds = [c for c in B.PROFILES[h["vendor"]]["commands"]
            if not c.get("auto") and not (h.get("pon_only") and c["scope"] == "onu")]
    if not cmds:
        return
    st.markdown("**More commands**")
    cols = st.columns(4)
    for n, c in enumerate(cmds):
        col = cols[n % 4]
        danger = bool(c.get("danger"))
        ok = True
        if danger:
            ok = col.checkbox(f"Confirm: {c['title']} (customer goes offline)", key=f"cf::{hid}::{c['title']}")
        if col.button(c["title"], key=f"act::{hid}::{c['title']}", disabled=not ok,
                      type="primary" if danger else "secondary", width="stretch"):
            if not pw:
                st.error("Enter the password in the sidebar first.")
                return
            with st.spinner(f"Running {c['title']} on {h['olt']}..."):
                try:
                    cmd, out = B.run_for_hit(h, c, user, pw)
                except Exception as e:
                    cmd, out = B.fill(c, h), f"(error: {B.err_text(e)})"
            h["details"].append((c["title"], cmd, out))
            st.rerun()


def render_ai(h, hid):
    facts = B.gather_facts(h)
    for tag, text in B.rule_lines(facts):
        {"ok": st.success, "bad": st.error, "warn": st.warning, "unknown": st.warning}.get(tag, st.info)(text)
    erp = st.text_area("ERP login status", key=f"erp::{hid}", height=80, placeholder="Paste the ERP text here")
    bw = st.text_area("MikroTik bandwidth", key=f"bw::{hid}", height=80, placeholder="Paste the bandwidth text here")
    ppp = st.text_area("MikroTik PPP", key=f"ppp::{hid}", height=80, placeholder="Paste the PPP text here")
    st.caption("Gemini only gives advice. It cannot run commands. Passwords in pasted text are removed.")
    if st.button("Analyze with Gemini", key=f"ai_btn::{hid}", type="primary"):
        key = (S.get("gem_key") or os.environ.get("GEMINI_API_KEY", "") or secret("GEMINI_API_KEY")).strip()
        if not key:
            st.error("Enter the Gemini API key in the sidebar.")
        else:
            with st.spinner("Asking Gemini..."):
                try:
                    text, model = B.ask_gemini(key, B.build_prompt(facts, erp, bw, ppp), S.settings)
                    S.ai[hid] = (text, f"Model: {model}")
                except Exception as e:
                    S.ai[hid] = (f"AI error: {e}", "")
    if hid in S.ai:
        st.markdown("**AI conclusion (Gemini)**")
        st.info(S.ai[hid][0])
        if S.ai[hid][1]:
            st.caption(S.ai[hid][1])


def render_hits(hits, prefix):
    for i, h in enumerate(hits):
        hid = f"{prefix}{i}"
        label = f"{h['sn_input']}  ·  {h['olt']}  ·  {B.hit_iface(h)}"
        if h.get("status"):
            label += f"  ·  {h['status']}"
        with st.expander(label, expanded=len(hits) == 1):
            st.code(B.hit_text(h), language=None)
            render_actions(h, hid)
            if not h.get("pon_only"):
                with st.expander("🤖 AI Analyze"):
                    render_ai(h, hid)


# ------------------------------------------------------------------ monitor
def build_monitor(st_res):
    now = datetime.now()
    rows, details = [], {}
    tot_new = tot_back = 0
    for r in sorted(st_res["rows"], key=lambda r: (r["olt"], B.natural_key(r.get("pon_label", r["pon_in"])))):
        iid = f"{r['olt_key']}|{r['pon_in']}"
        label = r.get("pon_label", r["pon_in"])
        if r["error"] or not r["cats"]:
            rows.append({"PON": label, "OLT": r["olt"], "Counts": "-", "Change": "-", "Status": "Error"})
            details[iid] = (f"{r['olt']}  PON {label}", r["error"] or "(no data)")
            continue
        cats = r["cats"]
        prev = S.snap.get(iid)
        new_keys, back_keys = B.monitor_diff(cats, prev["cats"] if prev else None)
        out = [f"{r['olt']}    PON {label}    updated {now:%H:%M:%S}, "
               + (f"previous {prev['time']:%H:%M:%S}" if prev else "baseline (first run)"), ""]
        for cat, title in (("LOSi", "LOSi / LOS / LOBi"), ("Offline", "Offline (all, incl. LOSi/DG)"),
                           ("Dying", "Dying Gasp"), ("Online", "Online")):
            if cat == "Online" and not cats["has_online"]:
                out += ["=== Online: BDCOM inactive list does not show online ONUs ===", ""]
                continue
            items = cats[cat]
            out.append(f"=== {title} ({len(items)}) ===")
            if not items:
                out.append("  (no ONUs)")
            for key in sorted(items, key=B.natural_key):
                is_new = bool(prev) and cat != "Online" and key not in prev["cats"].get(cat, {})
                cause = cats.get("causes", {}).get(key)
                out.append(("[NEW] " if is_new else "      ") + items[key].strip()
                           + (f"    <- cause: {cause}" if cause else ""))
            out.append("")
        if back_keys:
            out.append(f"=== BACK / recovered ({len(back_keys)}) ===")
            out += ["[BACK] " + prev["cats"]["Inactive"][k].strip() for k in sorted(back_keys, key=B.natural_key)]
            out.append("")
        out += ["=== Raw device data ===", r.get("raw") or "(nothing)"]
        online = str(len(cats["Online"])) if cats["has_online"] else "-"
        rows.append({"PON": label, "OLT": r["olt"],
                     "Counts": f"LOSi {len(cats['LOSi'])} | Offline {len(cats['Offline'])} | "
                               f"DG {len(cats['Dying'])} | Online {online}",
                     "Change": f"+{len(new_keys)} / -{len(back_keys)}" if prev else "baseline",
                     "Status": f"{now:%H:%M:%S}"})
        details[iid] = (f"{r['olt']}  PON {label}", "\n".join(out))
        S.snap[iid] = {"cats": cats, "time": now}
        tot_new += len(new_keys)
        tot_back += len(back_keys)
    return {"rows": rows, "details": details, "new": tot_new, "back": tot_back}


# ------------------------------------------------------------------ TAB: find
with tab_find:
    mode_label = st.radio("Search by", list(MODES), horizontal=True)
    mode = MODES[mode_label]
    pon_title = ""
    if mode == "pon":
        pon_title = st.selectbox("Command", B.PON_TITLES)
    hints = {"sn": "One ONU SN per line, e.g. HWTC:4577CE9A",
             "mac": "One router MAC per line (12 hex digits)",
             "onu": "BDCOM: 7 48 or 0/7:48     Huawei: 0/1/7 12 or 0/1/7:12",
             "pon": "BDCOM: 7 or 0/7     Huawei: 0/1/7",
             "monitor": "PON numbers, one per line. BDCOM: 7 or 0/7     Huawei: 0/1/7"}
    text = st.text_area("Input", height=110, placeholder=hints[mode], label_visibility="collapsed")
    check_dg = False
    if mode == "monitor":
        check_dg = st.checkbox("Dying Gasp check (slow: checks the cause of each Offline ONU)")
    go = st.button("Search", type="primary")

    if go:
        olts = selected_olts()
        user, pw = creds()
        olt_level = mode == "pon" and any(c["title"] == pon_title and c["scope"] == "olt"
                                          for pr in B.PROFILES.values() for c in pr["commands"])
        try:
            keys = parse_keys(mode, text, pon_title)
            if not olts:
                raise ValueError("Select at least one OLT in the sidebar.")
            if not keys and not olt_level:
                raise ValueError("Enter something to search for.")
            if not pw:
                raise ValueError("Enter the password in the sidebar.")
        except ValueError as e:
            st.error(str(e))
        else:
            S.settings.update({"user": user, "selected": [B.olt_key(o) for o in olts]})
            B.save_settings(S.settings)
            with st.spinner(f"Working on {len(olts)} OLT(s)... this can take a while."):
                try:
                    if mode in ("sn", "mac"):
                        stt = B.run_search(olts, keys, user, pw, mode=mode)
                        S.result = {"mode": mode, "hits": stt.hits, "missing": stt.remaining(),
                                    "done": len(stt.searched), "skipped": stt.skipped,
                                    "errors": stt.errors, "n": len(olts), "keys": keys}
                    elif mode == "onu":
                        stt = B.run_manual_onu(olts, keys, user, pw)
                        S.result = {"mode": mode, "hits": stt["hits"], "missing": [], "done": len(stt["done"]),
                                    "skipped": stt["skipped"], "errors": stt["errors"], "n": len(olts), "keys": keys}
                    elif mode == "pon":
                        stt = B.run_pon_status(olts, keys, pon_title, user, pw)
                        S.result = {"mode": mode, "hits": stt["rows"], "missing": [], "done": len(stt["done"]),
                                    "skipped": stt["skipped"], "errors": stt["errors"], "n": len(olts), "keys": keys}
                    else:
                        stt = B.run_pon_monitor(olts, keys, user, pw, check_dg=check_dg)
                        mon = build_monitor(stt)
                        S.result = {"mode": mode, "mon": mon, "done": len(stt["done"]), "skipped": stt["skipped"],
                                    "errors": stt["errors"], "n": len(olts), "keys": keys}
                except Exception as e:
                    S.result = None
                    st.error(f"Error: {B.err_text(e)}")

    res = S.result
    if res:
        summary_block(res["done"], res["skipped"], res["errors"], res["n"])
        if res["mode"] == "monitor":
            mon = res["mon"]
            st.write(f"**{len(mon['rows'])} PON(s)** · new inactive **+{mon['new']}** · recovered **-{mon['back']}**")
            if mon["rows"]:
                st.dataframe(mon["rows"], width="stretch", hide_index=True)
            for _iid, (title, body) in mon["details"].items():
                with st.expander(title):
                    st.code(body, language=None)
            if st.button("Reset baseline"):
                S.snap = {}
                st.rerun()
        else:
            if res["mode"] in ("sn", "mac"):
                st.write(f"Found **{len(res['hits'])}** / {len(res['keys'])}")
                for k in res["missing"]:
                    st.warning(f"'{k}' was not found on any of the selected OLTs.")
            render_hits(res["hits"], res["mode"])


# ------------------------------------------------------------------ TAB: today losi
def losi_scan(olts, user, pw):
    prog = st.progress(0.0, text="Checking OLTs...")
    done = [0]

    def status(_s):
        done[0] += 1                      # called from worker threads: only count here

    t0 = time.time()
    res = B.run_round(olts, user, pw, status)
    prog.empty()
    S.losi_raw = res["raw"]
    S.losi_time = datetime.now()
    S.losi_secs = time.time() - t0
    S.losi_n = len(olts)


def losi_olts():
    elig = B.eligible_olts(S.olts)
    watch = S.settings.get("watch")
    if watch is None:
        return elig
    return [o for o in elig if B.olt_key(o) in set(watch)]


with tab_losi:
    elig = B.eligible_olts(S.olts)
    names = {B.olt_key(o): o["name"] for o in elig}
    cur = S.settings.get("watch")
    default = [k for k in (cur if cur is not None else names) if k in names]
    watch = st.multiselect("OLTs to check", list(names), default=default, format_func=names.get)
    if sorted(watch) != sorted(default):
        S.settings["watch"] = watch
        B.save_settings(S.settings)

    c1, c2, c3 = st.columns([1, 1, 2])
    day = c1.date_input("Date", value=date.today(), format="DD/MM/YYYY")
    auto = c2.checkbox("Auto update every 15 min")
    refresh = c3.button("Refresh now", type="primary")

    user, pw = creds()
    olts_now = [o for o in elig if B.olt_key(o) in set(watch)]

    def maybe_scan(force):
        stale = S.losi_time is None or (datetime.now() - S.losi_time).total_seconds() > 14.5 * 60
        if not (force or (auto and stale)):
            return
        if not pw:
            st.error("Enter the password in the sidebar.")
        elif not olts_now:
            st.error("Select at least one OLT.")
        else:
            with st.spinner("Checking all OLTs (a few minutes)..."):
                losi_scan(olts_now, user, pw)

    def show_losi():
        if S.losi_raw is None:
            st.metric("Today Losi", "-", "Not updated yet")
            return
        res = B.summarize(S.losi_raw, day, S.get("losi_secs", 0), S.get("losi_n", 0), when=S.losi_time)
        color, main, sub = B.box_state(res)
        {"red": st.error, "green": st.success, "grey": st.warning}[color](f"**{main}**  \n{sub}")
        past = day != date.today()
        st.caption(f"Date {day:%d/%m/%Y} · {'Losi' if past else 'Today Losi'}: {res['total']} · "
                   f"Dying Gasp (not counted): {res['dg']} · updated {res['time']:%H:%M:%S}, "
                   f"took {B.fmt_secs(res['seconds'])} · OLTs checked {res['checked']}, "
                   f"failed {len(res['failed'])}, partly {res['partial']}")
        if res["wrong_pw"]:
            st.error("Wrong password. Auto update stopped.")
        for o in sorted(res["olts"], key=lambda x: (-x["count"], x["name"])):
            if o["error"]:
                st.error(f"{o['name']}: {o['error']}")
                continue
            if o["count"] == 0:
                continue
            with st.expander(f"{o['name']}  —  {o['count']}"):
                table = []
                for label in sorted(o["pons"], key=B.natural_key):
                    for e in sorted(o["pons"][label], key=lambda x: int(x["onu"])):
                        table.append({"PON": label, "ONU": e["onu"], "Down at": e["down"].strftime("%H:%M:%S"),
                                      "Cause": e["cause"] or "-", "SN": e["sn"]})
                st.dataframe(table, width="stretch", hide_index=True)
        if res["total"] == 0 and not res["failed"]:
            st.info("No ONU is down on this date.")

    maybe_scan(refresh)
    # auto mode: this fragment re-runs by itself every 15 minutes
    if auto:
        @st.fragment(run_every="15m")
        def _auto():
            maybe_scan(False)
            if S.losi_time:
                st.rerun()
        _auto()
    show_losi()


# ------------------------------------------------------------------ TAB: olt list
with tab_list:
    st.caption("Edit the OLT list. Vendor: bdcom / huawei / vsol / epon / other. Protocol: TELNET / SSH.")
    cols = ["group", "name", "host", "port", "protocol", "vendor"]
    edited = st.data_editor([{k: o.get(k, "") for k in cols} for o in S.olts], num_rows="dynamic",
                            width="stretch", key="olt_editor")
    if st.button("Save OLT list"):
        new = []
        for o in edited:
            if not str(o.get("name", "")).strip():
                continue
            o = dict(o)
            o["port"] = int(o["port"]) if str(o.get("port", "")).strip().isdigit() else 23
            o["protocol"] = str(o.get("protocol") or "TELNET").upper()
            o["vendor"] = o.get("vendor") or B.guess_vendor(o["name"])
            new.append(o)
        B.save_olts(new)
        S.olts = new
        for o in new:
            S.setdefault(f"sel::{B.olt_key(o)}", False)
        st.success(f"Saved {len(new)} OLTs.")
        st.rerun()
