# Streamlit – Google Contacts US (+1) Normalizer (No Secret Persistence)

This app scans your Google Contacts for **American-looking phone numbers** that are missing `+1`, suggests E.164 (`+14155551212`) formatting, lets you **select** rows to update, and applies *surgical* updates via the Google People API.

## Security model (Streamlit Cloud friendly)
- **No credentials are ever written to disk** by the app.
- You can authenticate in **two ways**, both kept **in session memory only**:
  1. **Paste token.json** (generated once on a trusted machine).
  2. **In-app OAuth** using a **Web application client** (client_id, client_secret, and an authorized redirect URI pointing to your deployed app).

## Features
- Paste **token.json** _or_ do **in-app OAuth** (PKCE) with your **Web** client.
- **Read-only scan** produces a table with confidence, notes, and a `suggested_e164` column.
- **Selectable dataframe** with `apply` checkboxes; **Select all visible / Clear all** helpers.
- **needs_update** and **updated_this_session** flags with default sorting (fix-first).
- **Cache for performance** (short TTL); cache is **busted after writes** to reflect live data.

## One-time token creation on a trusted machine (optional)
You can generate a `token.json` once locally using Google’s OAuth Desktop flow (outside this app), then paste it here.
- Enable the **People API** in your Google Cloud project.
- Create OAuth **Desktop app** credentials and run a small helper to obtain a token.
- Paste the resulting `token.json` into the app’s sidebar.

## Deploy steps (Streamlit Cloud, recommended path: in-app OAuth)
1. In Google Cloud Console → **APIs & Services → Credentials**:
   - Create **OAuth 2.0 Client ID → Web application**.
   - Set **Authorized redirect URI** to your deployed Streamlit app URL, e.g. `https://your-app.streamlit.app/`.
2. Deploy this repo to Streamlit Cloud.
3. In the app’s sidebar, choose **In-app OAuth**, paste `client_id`, `client_secret`, and the **exact** redirect URI, and click **Start Google sign-in**.

## Notes
- The app **never** writes `credentials.json` or `token.json` to disk.
- After **Apply**, the app clears its cache and re-fetches to show the updated values.
- Entries with extensions are flagged **low** confidence and not auto-applied.
- Only rows you mark `apply=True` are updated. Other fields and numbers are preserved.

