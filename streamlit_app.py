"""
Streamlit – Google Contacts US (+1) Normalizer (No Secret Persistence)

This application:
- Authenticates to the Google People API using **session-only** credentials.
- Scans your contacts, detecting American-looking numbers that should be normalized to E.164 (+1...).
- Presents a **selectable dataframe** so you can choose exactly which numbers to update.
- Applies **surgical updates** to the phoneNumbers field of each chosen contact.
- Uses short-lived caching of reads; after updates, cache is cleared to reflect live data.

SECURITY:
- The app does **not** write any credentials or tokens to disk.
- Auth modes:
  (A) "Paste token.json" – paste the full token JSON (with access & refresh token).
  (B) "In-app OAuth (Web client)" – paste client_id, client_secret, redirect URI; app performs PKCE OAuth in-session.

The code below is heavily documented so you can audit behavior line by line.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Tuple

import pandas as pd
import phonenumbers
import requests
import streamlit as st
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from phonenumbers import PhoneNumberFormat

# ---- Constants and configuration ----
SCOPES = ["https://www.googleapis.com/auth/contacts"]
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"

st.set_page_config(page_title="Contacts +1 Normalizer", page_icon="🇺🇸", layout="wide")
st.title("Google Contacts – US (+1) Normalizer")
st.caption("Secure (no secret persistence). Paste a token OR do in-app OAuth with a Web Client.")

# ---------------------------------------------------------------------------
#                                AUTH HELPERS
# ---------------------------------------------------------------------------

def set_creds(creds: Credentials) -> None:
    """
    Store a google.oauth2.credentials.Credentials object in Streamlit session_state.
    We only keep it in-memory for this session; we never write to disk.
    """
    st.session_state["creds"] = creds

def get_creds() -> Credentials | None:
    """Retrieve current credentials from session_state, or None if not authenticated."""
    return st.session_state.get("creds")

def google_service() -> Any:
    """
    Build an authenticated People API client from the in-memory credentials.
    If the access token is expired and a refresh_token exists, try to refresh.
    Fails fast with a clear message if auth is missing or unusable.
    """
    creds = get_creds()
    if not creds:
        st.stop()  # User hasn't authenticated yet; halt the app safely.

    # Attempt refresh if expired and a refresh_token is available.
    if not creds.valid and getattr(creds, "refresh_token", None):
        from google.auth.transport.requests import Request
        try:
            creds.refresh(Request())
        except Exception as e:
            st.error(f"Token refresh failed: {e}")
            st.stop()

    # If still invalid, we cannot proceed.
    if not creds.valid:
        st.error("Credentials invalid and no refresh token available. Re-authenticate.")
        st.stop()

    # Build the People API client; cache_discovery=False avoids unneeded caching on disk.
    return build("people", "v1", credentials=creds, cache_discovery=False)

# ---- PKCE utilities for OAuth "Web application" client ----

def _b64url(data: bytes) -> str:
    """Base64-url encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def start_pkce_flow(client_id: str, redirect_uri: str, scope: str = " ".join(SCOPES)) -> str:
    """
    Initialize a PKCE OAuth flow:
      - Generate a code_verifier and state token; store them in session.
      - Build the Google authorization URL.
      - Caller will render this URL as a link to start the sign-in.

    NOTE: The redirect_uri must exactly match one of the Web Client's authorized URIs.
    """
    code_verifier = _b64url(os.urandom(40))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state = _b64url(os.urandom(24))

    # Persist PKCE data only in session
    st.session_state["oauth_pkce"] = {
        "code_verifier": code_verifier,
        "state": state,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "ts": int(time.time()),
    }

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",  # ensure a refresh_token is issued
        "include_granted_scopes": "true",
    }
    # Build the authorization URL safely
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return f"{AUTH_ENDPOINT}?{query}"

def handle_oauth_redirect(client_id: str, client_secret: str) -> tuple[bool, str]:
    """
    Handle the OAuth redirect back to this app:
      - Extract `code` and `state` from the URL query params.
      - Verify state matches what we generated.
      - POST to the token endpoint to exchange code for tokens.
      - Build Credentials and store in session.

    Returns (ok, message). We never persist tokens to disk.
    """
    qp = st.query_params  # Streamlit >=1.27
    code = qp.get("code")
    state = qp.get("state")
    if not code or not state:
        return False, "No OAuth code/state in URL yet."
    if isinstance(code, list):
        code = code[0]
    if isinstance(state, list):
        state = state[0]

    pkce = st.session_state.get("oauth_pkce")
    if not pkce or pkce.get("state") != state:
        return False, "State mismatch. Restart sign-in."

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": pkce["redirect_uri"],
        "code_verifier": pkce["code_verifier"],
    }
    try:
        resp = requests.post(TOKEN_ENDPOINT, data=data, timeout=15)
        resp.raise_for_status()
        tok = resp.json()
        creds = Credentials(
            token=tok.get("access_token"),
            refresh_token=tok.get("refresh_token"),
            token_uri=TOKEN_ENDPOINT,
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPES,
        )
        set_creds(creds)
        st.success("Authenticated! You can remove ?code=...&state=... from the URL.")
        return True, "OK"
    except Exception as e:
        return False, f"Token exchange failed: {e}"

# ---------------------------------------------------------------------------
#                         PHONE ANALYSIS / SCAN LOGIC
# ---------------------------------------------------------------------------

EXT_REGEX = re.compile(r"(ext\.?|x|extension)\s*\d+$", re.IGNORECASE)

def has_extension(raw: str, parsed: phonenumbers.PhoneNumber) -> bool:
    """
    Return True if the parsed number includes an extension, or
    if the raw text ends with a common extension pattern.
    """
    if getattr(parsed, "extension", None):
        return True
    return bool(EXT_REGEX.search((raw or "").replace(" ", "")))

def analyze_number(raw_value: str) -> Dict[str, Any]:
    """
    Return analysis for a single phone value, including:
      - whether the number is already international (+...)
      - whether it validates for US and/or FR
      - a suggested E.164 value (+1...) if confidently US
      - confidence level: high / medium / low / skip
      - notes and extension flags

    We prioritize conservative changes:
      - If already starts with +, we skip.
      - If US-valid and FR-invalid: high confidence -> suggest +1.
      - If US-valid and FR-valid: medium confidence -> suggest +1 but mark ambiguous.
      - If extension detected: low confidence -> do not auto-apply.
    """
    value = (raw_value or "").strip()
    out = {
        "raw": raw_value,
        "already_international": value.startswith("+"),
        "us_valid": False,
        "fr_valid": False,
        "suggested_e164": "",
        "confidence": "skip",
        "notes": "",
        "has_extension": False,
    }

    if not value:
        out["notes"] = "empty"
        return out

    if value.startswith("+"):
        try:
            n_any = phonenumbers.parse(value, None)
            out["has_extension"] = has_extension(value, n_any)
            out["us_valid"] = phonenumbers.is_valid_number_for_region(n_any, "US")
            out["fr_valid"] = phonenumbers.is_valid_number_for_region(n_any, "FR")
            out["confidence"] = "skip"
            return out
        except phonenumbers.NumberParseException:
            out["notes"] = "unparseable_with_plus"
            return out

    # Try US parse
    try:
        n_us = phonenumbers.parse(value, region="US")
        us_valid = phonenumbers.is_valid_number_for_region(n_us, "US")
        out["us_valid"] = us_valid
    except phonenumbers.NumberParseException:
        out["notes"] = "unparseable_as_us"
        return out

    # Try FR parse to detect ambiguity
    try:
        n_fr = phonenumbers.parse(value, region="FR")
        fr_valid = phonenumbers.is_valid_number_for_region(n_fr, "FR")
        out["fr_valid"] = fr_valid
    except phonenumbers.NumberParseException:
        fr_valid = False

    out["has_extension"] = has_extension(value, n_us)

    if out["has_extension"]:
        out["confidence"] = "low"
        out["notes"] = (out["notes"] + "; " if out["notes"] else "") + "has_extension"
        if out["us_valid"]:
            out["suggested_e164"] = phonenumbers.format_number(n_us, PhoneNumberFormat.E164)
        return out

    if out["us_valid"]:
        if not fr_valid:
            out["suggested_e164"] = phonenumbers.format_number(n_us, PhoneNumberFormat.E164)
            out["confidence"] = "high"
            return out
        else:
            out["suggested_e164"] = phonenumbers.format_number(n_us, PhoneNumberFormat.E164)
            out["confidence"] = "medium"
            out["notes"] = (out["notes"] + "; " if out["notes"] else "") + "also_valid_fr"
            return out

    out["confidence"] = "skip"
    return out

# ---------------------------------------------------------------------------
#                          DATA FETCH / UPDATE LOGIC
# ---------------------------------------------------------------------------

@st.cache_data(show_spinner=False, ttl=60)
def fetch_connections(cache_bump:int, limit:int=0) -> List[Dict[str, Any]]:
    """
    Fetch a page-flattened list of connections with names and phoneNumbers.
    - cache_bump: integer used to bust cache after writes.
    - limit: optional cap on number of contacts fetched for quick tests.
    """
    svc = google_service()
    results: List[Dict[str, Any]] = []
    page_token = None
    fetched = 0
    while True:
        kwargs = dict(
            resourceName="people/me",
            pageSize=1000,
            personFields="names,phoneNumbers,metadata"
        )
        if page_token:
            kwargs["pageToken"] = page_token
        res = svc.people().connections().list(**kwargs).execute()
        for person in res.get("connections", []):
            results.append(person)
            fetched += 1
            if limit and fetched >= limit:
                return results
        page_token = res.get("nextPageToken")
        if not page_token:
            break
    return results

def build_rows(connections: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Transform People API connection payloads into a flat DataFrame used by the UI.
    Adds:
      - needs_update: True for US-valid numbers lacking a '+' that we can normalize.
      - updated_this_session: True if we updated this exact entry in this session.
    Sort order emphasizes actionable rows first.
    """
    rows = []
    for person in connections:
        rn = person.get("resourceName")
        etag = person.get("etag", "")
        name = ""
        names = person.get("names", [])
        if names:
            name = names[0].get("displayName") or names[0].get("unstructuredName") or ""
        phones = person.get("phoneNumbers", [])
        for idx, ph in enumerate(phones):
            raw = ph.get("value", "")
            ph_type = ph.get("type", "")
            res = analyze_number(raw)
            needs_update = bool(res["suggested_e164"]) and not res["already_international"]
            rows.append({
                "resourceName": rn,
                "etag": etag,
                "name": name,
                "phone_index": idx,
                "original_value": raw,
                "original_type": ph_type,
                "us_valid": res["us_valid"],
                "fr_valid": res["fr_valid"],
                "already_international": res["already_international"],
                "has_extension": res["has_extension"],
                "confidence": res["confidence"],
                "suggested_e164": res["suggested_e164"],
                "notes": res["notes"],
                "needs_update": needs_update,
                "apply": False,
            })
    df = pd.DataFrame(rows)

    # Mark which rows were updated this session using a stable key
    updated_keys = st.session_state.get("updated_keys", set())
    def key_of_row(r):
        return f"{r['resourceName']}|{r['phone_index']}|{r['original_value']}"
    if not df.empty:
        df["updated_this_session"] = df.apply(key_of_row, axis=1).isin(updated_keys)
        df = df.sort_values(
            by=["needs_update", "updated_this_session", "name"],
            ascending=[False, True, True]
        )
    else:
        df["updated_this_session"] = []
    return df

def update_selected(df: pd.DataFrame, max_updates:int=0) -> tuple[int, List[str], List[str]]:
    """
    Apply updates for rows where apply=True.
    - Groups edits by contact resourceName.
    - Fetches the latest contact (to get fresh etag & phoneNumbers list).
    - Updates only the 'value' of chosen phone indices.
    - Returns (changed_count, logs, changed_keys_for_session_state).
    """
    svc = google_service()
    changed = 0
    logs: List[str] = []
    changed_keys: List[str] = []
    grouped: Dict[str, List[Tuple[int, str, str]]] = {}

    # Group approved edits by contact
    for _, r in df.iterrows():
        if not r["apply"]:
            continue
        rn = r["resourceName"]
        idx = int(r["phone_index"])
        new_val = str(r["suggested_e164"])
        orig_val = str(r["original_value"])
        if not new_val.startswith("+"):
            logs.append(f"Skip {rn} idx {idx}: invalid suggested value")
            continue
        grouped.setdefault(rn, []).append((idx, new_val, orig_val))

    # Execute updates, respecting max_updates
    try:
        for rn, edits in grouped.items():
            if max_updates and changed >= max_updates:
                break
            person = svc.people().get(resourceName=rn, personFields="phoneNumbers,metadata").execute()
            etag = person.get("etag")
            phones = person.get("phoneNumbers", [])
            applied_here = 0
            for idx, new_val, orig_val in edits:
                if max_updates and changed >= max_updates:
                    break
                if 0 <= idx < len(phones):
                    phones[idx]["value"] = new_val
                    changed += 1
                    applied_here += 1
                    changed_keys.append(f"{rn}|{idx}|{orig_val}")
            if applied_here:
                body = {"etag": etag, "phoneNumbers": phones}
                svc.people().updateContact(
                    resourceName=rn,
                    updatePersonFields="phoneNumbers",
                    body=body
                ).execute()
                logs.append(f"Updated {rn}: {applied_here} number(s).")
    except HttpError as e:
        logs.append(f"ERROR: {e}")
    return changed, logs, changed_keys

# ---------------------------------------------------------------------------
#                                   UI
# ---------------------------------------------------------------------------

# Track cache busts and which rows we updated (for the session only)
if "cache_bump" not in st.session_state:
    st.session_state["cache_bump"] = 0
if "updated_keys" not in st.session_state:
    st.session_state["updated_keys"] = set()

# --- Sidebar: Authentication ---
with st.sidebar:
    st.header("Authentication")
    mode = st.radio(
        "Choose auth mode",
        ["Paste token.json", "In-app OAuth (Web client)"],
        captions=[
            "Paste a full token JSON (has access & refresh token).",
            "Use a Google Cloud **Web application** client (client_id & client_secret) + an authorized redirect URI pointing to this app.",
        ],
    )

    if mode == "Paste token.json":
        tok_text = st.text_area(
            "Paste token.json",
            height=220,
            placeholder='{"token":"...","refresh_token":"...","client_id":"...","client_secret":"...","scopes":["https://www.googleapis.com/auth/contacts"],"token_uri":"https://oauth2.googleapis.com/token","expiry":"..."}'
        )
        if tok_text.strip():
            try:
                tok_obj = json.loads(tok_text)
                creds = Credentials.from_authorized_user_info(tok_obj, SCOPES)
                set_creds(creds)
                st.success("Token loaded into session.")
            except Exception as e:
                st.error(f"Could not parse token.json: {e}")
    else:
        st.markdown("**Paste your Web Client** from Google Cloud → Credentials → OAuth 2.0 Client IDs → *Web application*.")
        client_id = st.text_input("client_id")
        client_secret = st.text_input("client_secret", type="password")
        redirect_uri = st.text_input("Authorized redirect URI (must exactly match Cloud Console)",
                                     placeholder="https://your-app.streamlit.app/")
        if client_id and client_secret and redirect_uri:
            auth_url = start_pkce_flow(client_id, redirect_uri)
            st.link_button("Start Google sign-in", auth_url, type="primary", use_container_width=True)
            ok, msg = handle_oauth_redirect(client_id, client_secret)
            if not get_creds():
                st.info("After signing in, you’ll be redirected back with `?code=...&state=...`. The app will auto-complete the exchange.")

# Optional: show scope summary
creds = get_creds()
if creds:
    st.sidebar.divider()
    st.sidebar.caption("Signed in")
    st.sidebar.write(f"Scopes: {', '.join(SCOPES)}")

# --- Sidebar: Scan controls ---
with st.sidebar:
    st.header("Scan options")
    limit = st.number_input("Limit contacts (0 = all)", min_value=0, step=100, value=0)
    only_high = st.checkbox("Only show HIGH confidence", value=True)
    col1, col2 = st.columns(2)
    if col1.button("🔍 Scan contacts", type="primary"):
        st.session_state["connections"] = fetch_connections(st.session_state["cache_bump"], limit)
    if col2.button("♻️ Clear cache"):
        fetch_connections.clear()
        st.session_state.pop("connections", None)
        st.success("Cache cleared.")

# Require a scan before proceeding
connections = st.session_state.get("connections")
if connections is None:
    st.info("Authenticate, then click **Scan contacts** to begin (read-only).")
    st.stop()

st.success(f"Fetched {len(connections)} contacts.")

# Build the working DataFrame and apply optional filter
df = build_rows(connections)
if only_high:
    df = df[df["confidence"] == "high"].copy()

# Summary panel for quick sanity checks
with st.expander("Summary", expanded=True):
    st.write("By confidence:")
    st.write(df["confidence"].value_counts(dropna=False))
    st.write("Needs update:", int(df["needs_update"].sum()))
    st.write("Updated this session:", int(df["updated_this_session"].sum()))

# Selection helpers and data editor
st.markdown("### Review & select rows to apply")
sel_col1, sel_col2 = st.columns([1, 1])
if sel_col1.button("Select all visible"):
    df["apply"] = True
if sel_col2.button("Clear all selections"):
    df["apply"] = False

edited = st.data_editor(
    df,
    num_rows="dynamic",
    use_container_width=True,
    column_config={
        "apply": st.column_config.CheckboxColumn(required=False, help="Mark to update this number"),
        "suggested_e164": st.column_config.TextColumn(disabled=True),
        "original_value": st.column_config.TextColumn(disabled=True),
        "name": st.column_config.TextColumn(disabled=True),
        "original_type": st.column_config.TextColumn(disabled=True),
        "confidence": st.column_config.TextColumn(disabled=True),
        "notes": st.column_config.TextColumn(disabled=True),
        "needs_update": st.column_config.CheckboxColumn(disabled=True),
        "updated_this_session": st.column_config.CheckboxColumn(disabled=True),
    },
    hide_index=True,
)

# Compute how many updates are selected
sel_count = int(edited["apply"].sum())
st.write(f"Selected rows: **{sel_count}**")

# Apply control and execution
max_updates = st.number_input("Max updates this run (0 = no cap)", min_value=0, value=25, step=5)
apply_btn = st.button("✅ Apply selected updates")

if apply_btn:
    # Merge to ensure we have the latest suggested_e164 for the selected rows
    key_cols = ["resourceName", "phone_index", "original_value"]
    approved = edited[edited["apply"]].merge(df[key_cols + ["suggested_e164"]], on=key_cols, how="left")

    changed, logs, changed_keys = update_selected(approved, max_updates=max_updates)
    if changed:
        st.success(f"Updated {changed} phone entr{'y' if changed==1 else 'ies'}.")

        # Remember what we changed for this session (for the "updated_this_session" flag)
        st.session_state["updated_keys"].update(changed_keys)

        # Bust the cache and re-fetch to reflect live state
        st.session_state["cache_bump"] += 1
        fetch_connections.clear()
        st.session_state["connections"] = fetch_connections(st.session_state["cache_bump"], limit)
    else:
        st.info("No updates applied.")

    # Show verbose logs for transparency
    with st.expander("Details"):
        for line in logs:
            st.text(line)

# Let the user export the current table (e.g., for offline review)
st.download_button(
    "⬇️ Download current review CSV",
    edited.to_csv(index=False).encode("utf-8"),
    file_name="review_contacts.csv",
    mime="text/csv",
)
