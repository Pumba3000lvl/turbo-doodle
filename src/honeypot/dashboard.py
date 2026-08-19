"""Streamlit dashboard to view honeypot events from honeypot.db
Run: streamlit run src/honeypot/dashboard.py
"""
import os
import sqlite3
from datetime import datetime, date
import io
import re
import pandas as pd
import streamlit as st

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DB_PATH = os.path.join(BASE, 'honeypot.db')

st.set_page_config(page_title='Honeypot Dashboard', layout='wide')
st.title('Honeypot Events Dashboard')

if not os.path.exists(DB_PATH):
    st.warning('Database not found. Запустите honeypot, чтобы собрать события (honeypot.db).')
    st.stop()

# helpers
@st.cache_data
def load_events(limit=1000):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('SELECT * FROM events ORDER BY ts DESC LIMIT ?', conn, params=(limit,))
    conn.close()
    # normalize types
    if 'ts' in df.columns:
        try:
            df['ts'] = pd.to_datetime(df['ts'])
        except Exception:
            pass
    return df

@st.cache_data
def load_all_events():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query('SELECT * FROM events ORDER BY ts DESC', conn)
    conn.close()
    if 'ts' in df.columns:
        try:
            df['ts'] = pd.to_datetime(df['ts'])
        except Exception:
            pass
    return df

# suspicious password heuristics
WEAK_PASSWORDS = {
    '123456', 'password', 'admin', 'qwerty', '1234', '12345', 'letmein', 'root', 'toor'
}

def is_suspicious_password(pw):
    if not pw:
        return False
    s = str(pw)
    if s.lower() in WEAK_PASSWORDS:
        return True
    if len(s) < 6:
        return True
    # repeated char sequences (e.g., aaaa)
    if re.fullmatch(r'(.)\1{3,}', s):
        return True
    # sequential digits/letters simple check
    if re.search(r'1234|2345|abcd|qwer', s.lower()):
        return True
    return False

# sidebar filters
st.sidebar.header('Filters')
row_limit = st.sidebar.number_input('Rows to load (most recent)', min_value=50, max_value=10000, value=1000, step=50)
load_all = st.sidebar.checkbox('Load all events (may be slow)', value=False)
use_regex = st.sidebar.checkbox('Use regex search', value=False)

if load_all:
    df = load_all_events()
else:
    df = load_events(limit=row_limit)

# time range filter (if timestamps available)
if not df.empty and 'ts' in df.columns:
    try:
        min_date = df['ts'].min().date()
        max_date = df['ts'].max().date()
    except Exception:
        min_date = date.today()
        max_date = date.today()
    start_date, end_date = st.sidebar.date_input('Time range', value=(min_date, max_date))
    # ensure tuple
    if isinstance(start_date, date) and isinstance(end_date, date):
        df = df[(df['ts'].dt.date >= start_date) & (df['ts'].dt.date <= end_date)]

event_types = sorted(df['event_type'].dropna().unique().tolist()) if not df.empty else []
selected_types = st.sidebar.multiselect('Event types', options=event_types, default=event_types)

ip_filter = st.sidebar.text_input('IP filter (contains)')
search_text = st.sidebar.text_input('Search username/password/command')

# apply filters
if selected_types:
    df = df[df['event_type'].isin(selected_types)]
if ip_filter:
    df = df[df['src_ip'].astype(str).str.contains(ip_filter, na=False)]

# search: substring or regex
if search_text:
    if use_regex:
        try:
            pattern = re.compile(search_text, re.IGNORECASE)
            df = df[df.apply(lambda r: bool(pattern.search(str(r.get('username','')))) or bool(pattern.search(str(r.get('password','')))) or bool(pattern.search(str(r.get('command','')))), axis=1)]
        except re.error as e:
            st.sidebar.error(f'Invalid regex: {e}')
    else:
        mask = df[['username','password','command']].fillna('').apply(lambda row: row.str.contains(search_text, case=False, na=False))
        df = df[mask.any(axis=1)]

# flag suspicious passwords
if not df.empty and 'password' in df.columns:
    df['pw_suspicious'] = df['password'].apply(is_suspicious_password)
else:
    df['pw_suspicious'] = False

suspicious_count = int(df['pw_suspicious'].sum()) if not df.empty else 0
st.sidebar.markdown(f'**Suspicious passwords:** {suspicious_count}')

st.subheader(f'Events ({len(df):,})')

# summary
col1, col2 = st.columns([2,1])
with col1:
    # display with highlighting for suspicious passwords
    if not df.empty:
        display_df = df.reset_index(drop=True).copy()
        try:
            def highlight_password(col):
                return ['background-color: #ffeb99' if is_suspicious_password(v) else '' for v in col]
            styler = display_df.style.apply(highlight_password, subset=['password'])
            st.dataframe(styler, use_container_width=True)
        except Exception:
            # fallback
            st.dataframe(display_df, use_container_width=True)
    else:
        st.dataframe(df, use_container_width=True)
with col2:
    if not df.empty:
        counts = df['event_type'].value_counts()
        st.bar_chart(counts)
        st.markdown('---')
        st.write('Recent IPs')
        st.table(df['src_ip'].value_counts().head(10))

# event details selector and display
if not df.empty:
    event_ids = df['id'].astype(str).tolist()
    selected_id = st.sidebar.selectbox('Select event ID to view details', options=event_ids)
    if selected_id:
        row = df[df['id'].astype(str) == selected_id].iloc[0]
        with st.expander(f'Event {selected_id} details'):
            detail = row.to_dict()
            if detail.get('pw_suspicious'):
                st.markdown('**Warning:** Suspicious password detected')
            # mask password in details
            masked = {k: (v if k != 'password' else ('*** (suspicious)' if detail.get('pw_suspicious') else '***')) for k,v in detail.items()}
            st.json(masked)

# download
def to_csv_bytes(df_in):
    buffer = io.StringIO()
    df_in.to_csv(buffer, index=False)
    return buffer.getvalue().encode('utf-8')

if not df.empty:
    csv_bytes = to_csv_bytes(df)
    st.download_button('Download CSV', data=csv_bytes, file_name='honeypot_events.csv', mime='text/csv')

st.sidebar.markdown('---')
st.sidebar.markdown('Run ssh honeypot: python run_ssh.py')
st.sidebar.markdown('Run http honeypot: python src/honeypot/http_honeypot.py')
