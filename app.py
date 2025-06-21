# app.py (The Unified Threat Analyzer Platform)

import streamlit as st
import pandas as pd
import sqlite3
import json
from collections import Counter

# --- Local Application Imports ---
# These now live inside the same project
from modules.structural_analyzer import analyze_structure
from modules.link_analyzer import analyze_links
from modules.nlp_analyzer import analyze_linguistics
from modules.scoring_engine import calculate_score

# --- Page Configuration ---
st.set_page_config(
    page_title="Threat Analyzer Platform",
    page_icon="🛡️",
    layout="wide"
)

# --- Database Setup and Functions ---
DB_FILE = "threat_analysis_data.db"

def initialize_database():
    """Creates the database and table if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        message_body TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        findings_json TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

@st.cache_data # Use caching for performance
def load_data():
    """Loads all analysis results from the database into a Pandas DataFrame."""
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM analysis_results", conn)
    conn.close()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['findings_list'] = df['findings_json'].apply(lambda x: json.loads(x or "[]"))
    return df

def save_analysis(message, score, findings):
    """Saves a new analysis result to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    findings_as_json_string = json.dumps(findings)
    cursor.execute("INSERT INTO analysis_results (message_body, threat_score, findings_json) VALUES (?, ?, ?)", 
                   (message, score, findings_as_json_string))
    conn.commit()
    conn.close()
    # When new data is saved, we clear the cache so the dashboard reloads with fresh data
    st.cache_data.clear()

# --- Core Analysis Function ---
def run_full_analysis(message_body):
    """A single function to run a message through all analysis modules."""
    all_findings = []
    all_findings.extend(analyze_structure(message_body))
    all_findings.extend(analyze_links(message_body))
    all_findings.extend(analyze_linguistics(message_body))
    score = calculate_score(all_findings)
    return score, all_findings

# --- UI Layout (Using Streamlit's Multi-Page App feature) ---

# Initialize the database on the first run of the script
initialize_database()

st.sidebar.title("Threat Analyzer Platform")
# Use a selectbox for navigation, which is a common pattern for multi-page apps
page = st.sidebar.selectbox("Choose a page:", ["Real-Time Detector", "Intelligence Dashboard"])

# --- Page 1: Real-Time Detector ---
if page == "Real-Time Detector":
    st.header("Real-Time Threat Detector 🕵️‍♀️")
    st.write("Analyze a single message for potential threats. The result will be automatically saved to the database for trend analysis.")

    message_input = st.text_area("Enter the message text to analyze:", height=200, key="detector_input")

    if st.button("Analyze Message"):
        if message_input:
            with st.spinner("Analyzing..."):
                score, findings = run_full_analysis(message_input)
                
                # Save the result to the database automatically
                save_analysis(message_input, score, findings)
                st.success("Analysis complete and result saved to the database!")
                
                # Display the immediate result
                st.subheader("Analysis Report")
                st.metric(label="Calculated Threat Score", value=score)
                st.write("**Detected Findings:**")
                if findings:
                    for finding in findings:
                        st.warning(f"⚠️ {finding.replace('_', ' ').title()}")
                else:
                    st.success("✅ No suspicious findings were detected.")
        else:
            st.warning("Please enter a message to analyze.")

# --- Page 2: Intelligence Dashboard ---
elif page == "Intelligence Dashboard":
    st.header("Threat Intelligence Dashboard 📊")
    
    df = load_data()
    
    if df.empty:
        st.info("The database is empty. Please use the 'Real-Time Detector' to analyze some messages first.")
    else:
        # Add filters to the sidebar for the dashboard page
        st.sidebar.markdown("---")
        st.sidebar.header("Dashboard Filters")
        
        min_date = df['timestamp'].min().date()
        max_date = df['timestamp'].max().date()
        date_range = st.sidebar.date_input("Filter by Date Range", (min_date, max_date), min_value=min_date, max_value=max_date)
        
        # NEW, IMPROVED CODE
        min_score = int(df['threat_score'].min())
        max_score = int(df['threat_score'].max())

        # Add a check to prevent the slider error if all scores are the same
        if min_score == max_score:
            max_score = min_score + 1 # Artificially create a range
            
        score_range = st.sidebar.slider(
            "Filter by Threat Score", 
            min_value=min_score, 
            max_value=max_score, 
            value=(min_score, max_score) # The default selection remains the same
        )

        # --- Filtering Logic ---
        start_date = pd.to_datetime(date_range[0])
        end_date = pd.to_datetime(date_range[1]) + pd.Timedelta(days=1)

        filtered_df = df[
            (df['timestamp'] >= start_date) & (df['timestamp'] < end_date) &
            (df['threat_score'] >= score_range[0]) & (df['threat_score'] <= score_range[1])
        ]

        # --- Dashboard Metrics and Charts ---
        st.subheader("High-Level Metrics")
        kpi1, kpi2, kpi3 = st.columns(3)
        kpi1.metric("Total Messages in View", value=len(filtered_df))
        avg_score = filtered_df['threat_score'].mean() if not filtered_df.empty else 0
        kpi2.metric("Average Threat Score", value=f"{avg_score:.2f}")
        high_risk_percentage = (filtered_df['threat_score'] > 50).mean() * 100 if not filtered_df.empty else 0
        kpi3.metric("High-Risk Messages (%)", value=f"{high_risk_percentage:.2f}%")

        st.markdown("---")
        
        # Explode the dataframe for accurate chart counts
        df_findings = filtered_df.explode('findings_list').dropna(subset=['findings_list'])
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Top Detected Threat Types")
            finding_base_names = df_findings['findings_list'].apply(lambda x: str(x).split(':')[0])
            finding_counts = finding_base_names.value_counts().head(10)
            st.bar_chart(finding_counts)
        with col2:
            st.subheader("Threats Over Time")
            threats_by_day = filtered_df.set_index('timestamp').resample('D')['threat_score'].count()
            st.line_chart(threats_by_day)

        st.markdown("---")
        st.subheader("Filtered Data Explorer")
        st.dataframe(filtered_df)