import streamlit as st
import math
import pandas as pd
import plotly.express as px

# 頁面配置
st.set_page_config(
    page_title="密碼學破解時間估計器",
    page_icon="🔐",
    layout="wide"
)

# 標題與簡介
st.title("🔐 密碼學破解時間估計與安全性分析 App")
st.markdown("""
本工具協助理解不同長度、複雜度與加密演算法在面對**暴力破解攻擊 (Brute-Force Attack)** 時的安全性等級，
並提供實務上的安全性評估與建議。
""")

# 頁籤選單
tab1, tab2, tab3 = st.tabs(["🔑 密碼強度估計 (Password Brute-force)", "🛡️ 密碼學金鑰分析 (Symmetric & Asymmetric Keys)", "📚 密碼學概念與建議"])

# ==========================================
# 輔助函式：時間格式化
# ==========================================
def format_time(seconds):
    if seconds < 1e-6:
        return "微秒級 (瞬間)"
    elif seconds < 1:
        return f"{seconds*1000:.2f} 毫秒"
    elif seconds < 60:
        return f"{seconds:.2f} 秒"
    elif seconds < 3600:
        return f"{seconds/60:.2f} 分鐘"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} 小時"
    elif seconds < 86400 * 365:
        return f"{seconds/86400:.2f} 天"
    elif seconds < 86400 * 365 * 10000:
        years = seconds / (86400 * 365)
        return f"{years:,.2f} 年"
    elif seconds < 86400 * 365 * 1e8:
        years = seconds / (86400 * 365 * 1e4)
        return f"{years:,.2f} 萬年"
    elif seconds < 86400 * 365 * 1.38e10:
        years = seconds / (86400 * 365 * 1e8)
        return f"{years:,.2f} 億年"
    else:
        universe_age_ratio = seconds / (86400 * 365 * 1.38e10)
        return f"{universe_age_ratio:,.2e} 倍宇宙年齡 (約 {seconds/(86400*365*1e8):,.0f} 億年)"

# ==========================================
# TAB 1: 密碼強度估計
# ==========================================
with tab1:
    st.header("🔑 密碼暴力破解時間估算")
    
    col_input, col_speed = st.columns([1, 1])
    
    with col_input:
        st.subheader("1. 輸入密碼或自訂字元集")
        input_mode = st.radio("模式選擇", ["直接輸入密碼進行檢測", "自訂字元集與長度"])
        
        if input_mode == "直接輸入密碼進行檢測":
            user_password = st.text_input("輸入欲測試的密碼（僅於本地計算，不會儲存）：", value="P@ssw0rd2026", type="password")
            
            # 計算密碼特徵
            length = len(user_password)
            has_lower = any(c.islower() for c in user_password)
            has_upper = any(c.isupper() for c in user_password)
            has_digit = any(c.isdigit() for c in user_password)
            has_symbol = any(not c.isalnum() for c in user_password)
            
            charset_size = 0
            if has_lower: charset_size += 26
            if has_upper: charset_size += 26
            if has_digit: charset_size += 10
            if has_symbol: charset_size += 33
            if charset_size == 0 and length > 0:
                charset_size = 95 # 預設 ASCII 可列印字元
            
            st.info(f"""
            **密碼分析結果：**
            - 長度：**{length}** 字元
            - 包含字元類別：小寫 ({'✓' if has_lower else '✗'}) | 大寫 ({'✓' if has_upper else '✗'}) | 數字 ({'✓' if has_digit else '✗'}) | 符號 ({'✓' if has_symbol else '✗'})
            - 推估字元集基數 (Charset Size $N$)：**{charset_size}**
            """)
        else:
            length = st.slider("密碼長度 ($L$)", min_value=1, max_value=64, value=12)
            use_lower = st.checkbox("小寫字母 (a-z, 26字)", value=True)
            use_upper = st.checkbox("大寫字母 (A-Z, 26字)", value=True)
            use_digits = st.checkbox("數字 (0-9, 10字)", value=True)
            use_symbols = st.checkbox("特殊符號 (!@#..., 33字)", value=True)
            
            charset_size = 0
            if use_lower: charset_size += 26
            if use_upper: charset_size += 26
            if use_digits: charset_size += 10
            if use_symbols: charset_size += 33
            
            if charset_size == 0:
                st.warning("請至少選擇一種字元類別！")
                charset_size = 1

    with col_speed:
        st.subheader("2. 選擇攻擊情境與計算硬體")
        
        hash_algo = st.selectbox(
            "哈希/驗證機制演算法 (計算速度差異顯著)",
            [
                "極速哈希 (MD5 / NTLM - 常用於舊系統/ Windows 密碼)",
                "中速哈希 (SHA-256 - 一般雜湊)",
                "慢速慢雜湊 (Bcrypt / Argon2 / PBKDF2 - 現代安全儲存)",
                "線上登入嘗試 (受限於網路與 lockout 政策)",
                "自訂攻擊速度 (Guesses/sec)"
            ]
        )
        
        # 根據選擇設定預設攻擊速度
        if "極速哈希" in hash_algo:
            attack_speed = st.number_input("攻擊速度 (嘗試幾次/秒)", value=100_000_000_000, format="%d", help="1000 億次/秒 (如高階多 GPU 算力集群)")
        elif "中速哈希" in hash_algo:
            attack_speed = st.number_input("攻擊速度 (嘗試幾次/秒)", value=10_000_000_000, format="%d", help="100 億次/秒")
        elif "慢速慢雜湊" in hash_algo:
            attack_speed = st.number_input("攻擊速度 (嘗試幾次/秒)", value=100_000, format="%d", help="10 萬次/秒 (因 key stretching 降低速度)")
        elif "線上登入" in hash_algo:
            attack_speed = st.number_input("攻擊速度 (嘗試幾次/秒)", value=10, format="%d", help="10 次/秒 (線上 API 限制)")
        else:
            attack_speed = st.number_input("自訂攻擊速度 (嘗試幾次/秒)", value=1_000_000_000, format="%d")

    # 計算核心
    st.divider()
    st.subheader("📊 破解時間計算結果")
    
    if length > 0 and charset_size > 0 and attack_speed > 0:
        combinations = charset_size ** length
        entropy = length * math.log2(charset_size) if charset_size > 1 else 0
        
        # 平均嘗試次數為總空間的一半 (50%)
        avg_attempts = combinations / 2
        time_worst_sec = combinations / attack_speed
        time_avg_sec = avg_attempts / attack_speed
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("組合總數 ($N^L$)", f"{combinations:.2e}")
        c2.metric("資訊熵 (Entropy)", f"{entropy:.1f} bits")
        c3.metric("平均破解時間", format_time(time_avg_sec))
        c4.metric("最壞情況時間", format_time(time_worst_sec))
        
        # 安全性評級
        if entropy < 40:
            st.error("🔴 安全等級：極危險 (Extremely Weak) - 容易在極短時間內被字典檔或暴力破解！")
        elif entropy < 60:
            st.warning("🟠 安全等級：中等偏弱 (Weak) - 面對專用 GPU 離線破解仍不夠安全。")
        elif entropy < 80:
            st.info("🟡 安全等級：良好 (Good) - 一般情境下足以防禦暴力攻擊。")
        else:
            st.success("🟢 安全等級：極強 (Very Strong) - 在現有計算能力下幾乎不可能被暴力破解。")
            
        # 多攻擊場景比較圖表
        st.subheader("📈 不同硬體/情境下平均破解時間對比")
        scenarios = {
            "線上攻擊 (10次/秒)": 10,
            "普通 CPU 破解 (100萬次/秒)": 1e6,
            "單張 RTX 4090 GPU (100億次/秒)": 1e10,
            "頂級 GPU 算力陣列 (1000億次/秒)": 1e11,
            "國家級超級電腦 (10兆次/秒)": 1e13
        }
        
        data = []
        for name, speed in scenarios.items():
            sec = avg_attempts / speed
            days = sec / 86400
            data.append({"攻擊情境": name, "破解時間 (秒)": sec, "對數時間 log10(秒)": math.log10(max(sec, 1e-9)), "可讀時間": format_time(sec)})
            
        df_scenarios = pd.DataFrame(data)
        
        fig = px.bar(
            df_scenarios, 
            x="攻擊情境", 
            y="對數時間 log10(秒)", 
            hover_data=["可讀時間"],
            text="可讀時間",
            title="各攻擊情境所需時間 (對數尺度 Log10 Seconds)",
            color="對數時間 log10(秒)",
            color_continuous_scale="Reds_r"
        )
        fig.update_layout(xaxis_title="", yaxis_title="對數時間 log10(秒)")
        st.plotly_chart(fig, use_container_width=True)

# ==========================================
# TAB 2: 密碼學金鑰分析
# ==========================================
with tab2:
    st.header("🛡️ 對稱式與非對稱式金鑰強度分析")
    st.markdown("""
    密碼學金鑰的安全性通常以**位元長度 (Key Length in Bits)** 衡量。
    對稱加密（如 AES）直接窮舉 $2^{\\text{bits}}$ 個空間，而非對稱加密（如 RSA）則依賴數學難題（如大數分解），所需位元數顯著較長。
    """)
    
    col_key_type, col_key_result = st.columns([1, 1])
    
    with col_key_type:
        key_type = st.selectbox(
            "選擇加密演算法 / 金鑰規格",
            [
                "DES (56-bit) [已被破解]",
                "3DES (168-bit / 有效強度 112-bit)",
                "AES-128 (128-bit)",
                "AES-192 (192-bit)",
                "AES-256 (256-bit)",
                "RSA-1024 (1024-bit) [已不安全]",
                "RSA-2048 (2048-bit) [目前標準]",
                "RSA-4096 (4096-bit) [高安全性]",
                "ECC 256-bit (相當於 RSA-3072)"
            ]
        )
        
        # 決定有效位元數
        if "DES (56-bit)" in key_type:
            effective_bits = 56
            algo_type = "Symmetric"
        elif "3DES" in key_type:
            effective_bits = 112
            algo_type = "Symmetric"
        elif "AES-128" in key_type:
            effective_bits = 128
            algo_type = "Symmetric"
        elif "AES-192" in key_type:
            effective_bits = 192
            algo_type = "Symmetric"
        elif "AES-256" in key_type:
            effective_bits = 256
            algo_type = "Symmetric"
        elif "RSA-1024" in key_type:
            effective_bits = 80 # 對應對稱安全位元
            algo_type = "Asymmetric"
        elif "RSA-2048" in key_type:
            effective_bits = 112
            algo_type = "Asymmetric"
        elif "RSA-4096" in key_type:
            effective_bits = 128
            algo_type = "Asymmetric"
        elif "ECC 256-bit" in key_type:
            effective_bits = 128
            algo_type = "Asymmetric"
            
        # 修正：將數字範圍縮小至 JavaScript 安全整數範圍內 (改用 ExaFLOPS 為單位)
        exaflops = st.number_input(
            "全球頂級超級電腦總算力估計 (單位：ExaFLOPS, 1 ExaFLOPS = 10^18 次計算/秒)",
            value=1.0,
            min_value=0.0001,
            max_value=1000000.0,
            step=0.5,
            help="目前最頂尖超算（如 Frontier / El Capitan）約為 1 ~ 2 ExaFLOPS"
        )
        
        custom_ops = exaflops * 1e18  # 在 Python 後端轉換為實際運算次數

    with col_key_result:
        st.subheader("物理極限與破解時間估算")
        
        total_keys = 2 ** effective_bits
        avg_attempts_key = total_keys / 2
        years_to_crack = (avg_attempts_key / custom_ops) / (86400 * 365)
        
        st.metric("等效安全位元數 (Security Strength)", f"{effective_bits} bits")
        st.metric("金鑰空間大小 ($2^{{{effective_bits}}}$)", f"2^{effective_bits} ≈ {total_keys:.2e}")
        st.metric("全球頂級超算破解平均時間", format_time(avg_attempts_key / custom_ops))
        
        if effective_bits <= 56:
            st.error("❌ 狀態：已遭破解。DES 可以在幾小時內被現成硬體破解。")
        elif effective_bits <= 80:
            st.warning("⚠️ 狀態：不建議使用。國家級單位有能力破解。")
        elif effective_bits <= 112:
            st.info("🟡 狀態：短期安全，但正逐漸淘汰 (例如 RSA-2048 / 3DES)。")
        else:
            st.success("🟢 狀態：極度安全。在現有物理學與計算理論下無法暴力破解。")

    # 熱力學與物理極限科普
    st.divider()
    st.subheader("💡 密碼學小知識：256-bit 加密的物理極限")
    st.markdown("""
    根據**朗道爾原理 (Landauer's Principle)**，在室溫下翻轉 1 位元資訊所需的最小能量為 $E = k_B T \\ln 2 \\approx 2.85 \\times 10^{-21}$ 焦耳。
    * 要窮舉 AES-256 的 $2^{256}$ 次狀態：
      需要消耗約 **$3.3 \\times 10^{56}$ 焦耳** 的能量。
    * 作為對比：**整個太陽系一年釋放的所有能量**約為 $1.2 \\times 10^{34}$ 焦耳。
    * 結論：**暴力破解 AES-256 所需要的能量，超過煮沸地球上所有海洋數百萬次所需能量。** 因此，密碼學攻擊絕非透過暴力破解，而是尋找演算法實作漏洞或金鑰管理瑕疵。
    """)

# ==========================================
# TAB 3: 密碼學概念與實務建議
# ==========================================
with tab3:
    st.header("📚 資訊安全防禦與密碼原則")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("🔑 高強度密碼制定原則")
        st.markdown("""
        1. **長度勝於複雜度 (Length > Complexity)**：
           - `correcthorsebatterystaple` (25字元純小寫，資訊熵約 117 bits) 比 `P@ss12` (6字元，資訊熵約 39 bits) 安全數十億倍且更容易記憶。
        2. **使用密碼管理器 (Password Manager)**：
           - 讓工具幫每個網站生成獨立、隨機的 16+ 位元密碼 (例如 1Password, Bitwarden, KeePass)。
        3. **絕對不要跨網站重複使用密碼**：
           - 預防**撞庫攻擊 (Credential Stuffing)**。
        """)
        
    with col_b:
        st.subheader("🛡️ 企業端安全儲存機制")
        st.markdown("""
        1. **加鹽 (Salting)**：
           - 為每個使用者密碼加上隨機亂數再進行哈希，防範**彩虹表 (Rainbow Table)** 預先計算攻擊。
        2. **Key Stretching (慢雜湊)**：
           - 使用 **Argon2id**, **bcrypt**, 或 **PBKDF2**，刻意增加計算開銷與記憶體需求，拉長攻擊者暴力破解的時間。
        3. **量子計算對密碼學的影響**：
           - **Grover 演算法**：使對稱加密 (AES) 強度減半 (AES-256 降至 128-bit 安全度，依然安全)。
           - **Shor 演算法**：可在多項式時間內破解 RSA/ECC，因此業界正全力推動**後量子密碼學 (PQC, Post-Quantum Cryptography)**。
        """)
