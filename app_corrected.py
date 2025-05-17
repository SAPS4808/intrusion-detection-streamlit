
import streamlit as st
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ✅ This must be the first Streamlit command
st.set_page_config(page_title="AI Intrusion Detection System", layout="wide")

# UI
st.title("🛡️ Intrusion Detection System")
st.markdown("Upload a CSV file with network traffic to scan for possible threats.")

# Load model
@st.cache_resource
def load_model():
    return joblib.load("xgb_ids_model.pkl")

model = load_model()

# Upload file
uploaded_file = st.file_uploader("📂 Upload CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success("✅ File uploaded successfully!")

    # Preprocess
    with st.spinner("Preprocessing data..."):
        drop_cols = ['srcip', 'dstip', 'sport', 'dsport', 'Stime', 'Ltime', 'attack_cat']
        df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
        df = df.dropna(axis=1, how='all')

        # Encode categoricals
        cat_cols = df.select_dtypes(include='object').columns.tolist()
        for col in cat_cols:
            df[col] = LabelEncoder().fit_transform(df[col].astype(str))

        X = df.drop(columns='label', errors='ignore')
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

    # Prediction
    with st.spinner("Analyzing traffic..."):
        preds = model.predict(X_scaled)
        df['prediction'] = preds

    # Results
    malicious = df[df['prediction'] == 1]
    benign = df[df['prediction'] == 0]

    st.subheader("🔎 Scan Summary")
    st.info(f"🟢 Safe connections: {len(benign)}")
    st.error(f"🔴 Potential threats detected: {len(malicious)}")

    if not malicious.empty:
        st.subheader("⚠️ Suspicious Connections (Top 5)")
        st.dataframe(malicious.head(5), use_container_width=True)
    else:
        st.success("🎉 No threats detected. Network appears clean.")
