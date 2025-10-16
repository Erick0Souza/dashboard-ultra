import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
import bcrypt

# --- Banco de Dados ---
conn = sqlite3.connect('usuarios.db', check_same_thread=False)
cursor = conn.cursor()

# --- Criação de tabelas ---
cursor.execute('''
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    idade INTEGER,
    criado_em TEXT,
    criado_por TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    senha_hash TEXT NOT NULL,
    role TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS historico (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    acao TEXT NOT NULL,
    usuario TEXT,
    target_id INTEGER,
    timestamp TEXT
)
''')
conn.commit()

# --- Inicializa admin ---
cursor.execute("SELECT * FROM auth WHERE username='admin'")
if cursor.fetchone() is None:
    senha_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
    cursor.execute("INSERT INTO auth (username, senha_hash, role) VALUES (?,?,?)", ("admin", senha_hash, "admin"))
    conn.commit()

# --- Funções ---
def verificar_login(username, senha):
    cursor.execute("SELECT senha_hash, role FROM auth WHERE username=?", (username,))
    result = cursor.fetchone()
    if result and bcrypt.checkpw(senha.encode(), result[0]):
        return True, result[1]
    return False, None

def carregar_usuarios(filtro_nome=None, filtro_email=None, filtro_faixa=None):
    query = "SELECT * FROM usuarios WHERE 1=1"
    params = []
    if filtro_nome: 
        query += " AND nome LIKE ?"
        params.append(f"%{filtro_nome}%")
    if filtro_email: 
        query += " AND email LIKE ?"
        params.append(f"%{filtro_email}%")
    
    df = pd.read_sql_query(query, conn, params=params)
    df.columns = [c.lower() for c in df.columns]  # padroniza nomes de colunas
    
    if filtro_faixa:
        bins = [0,20,40,60,120]; labels = ["0-20","21-40","41-60","61+"]
        df['faixa'] = pd.cut(df['idade'], bins=bins, labels=labels)
        df = df[df['faixa'] == filtro_faixa]
    return df

def registrar_historico(acao, usuario, target_id=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO historico (acao, usuario, target_id, timestamp) VALUES (?,?,?,?)",
                   (acao, usuario, target_id, timestamp))
    conn.commit()

def adicionar_usuario(nome, email, idade, criado_por):
    try:
        agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO usuarios (nome,email,idade,criado_em,criado_por) VALUES (?,?,?,?,?)",
                       (nome,email,int(idade),agora,criado_por))
        conn.commit()
        ultimo_id = cursor.lastrowid
        registrar_historico("adicionar", criado_por, ultimo_id)
        st.success("Usuário adicionado!")
    except sqlite3.IntegrityError:
        st.error("Email já cadastrado!")

def deletar_usuario(user_id, usuario):
    cursor.execute("DELETE FROM usuarios WHERE id=?", (user_id,))
    conn.commit()
    registrar_historico("deletar", usuario, user_id)
    st.success("Usuário deletado!")

def atualizar_usuario(user_id, nome, email, idade, usuario):
    try:
        cursor.execute("UPDATE usuarios SET nome=?, email=?, idade=? WHERE id=?",
                       (nome,email,int(idade),user_id))
        conn.commit()
        registrar_historico("atualizar", usuario, user_id)
        st.success("Usuário atualizado!")
    except sqlite3.IntegrityError:
        st.error("Email já cadastrado!")

def exportar_csv(df):
    if not df.empty:
        df.to_csv("usuarios_export.csv", index=False)
        st.success("Dados exportados para usuarios_export.csv")
    else:
        st.warning("Não há dados para exportar.")

def importar_csv(file, usuario):
    df = pd.read_csv(file)
    df.columns = [c.lower() for c in df.columns]
    for _, row in df.iterrows():
        try:
            agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('INSERT OR IGNORE INTO usuarios (id,nome,email,idade,criado_em,criado_por) VALUES (?,?,?,?,?,?)',
                           (row.get('id'), row.get('nome'), row.get('email'), row.get('idade'), agora, usuario))
        except:
            pass
    conn.commit()
    st.success("CSV importado com sucesso!")

# --- Login ---
st.sidebar.title("Login")
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'role' not in st.session_state: st.session_state.role = None
if 'user' not in st.session_state: st.session_state.user = None

if not st.session_state.logged_in:
    username = st.sidebar.text_input("Usuário")
    password = st.sidebar.text_input("Senha", type="password")
    login_btn = st.sidebar.button("Entrar")
    if login_btn:
        ok, role = verificar_login(username, password)
        if ok:
            st.session_state.logged_in = True
            st.session_state.role = role
            st.session_state.user = username
            st.sidebar.success(f"Logado como {username} ({role})")
        else:
            st.sidebar.error("Usuário ou senha inválidos")
else:
    st.sidebar.success(f"Logado como {st.session_state.user} ({st.session_state.role})")

# --- Dashboard ---
if st.session_state.logged_in:
    st.title("Dashboard Ultra-Profissional de Usuários")

    # --- Filtros ---
    st.sidebar.subheader("Filtros Avançados")
    filtro_nome = st.sidebar.text_input("Nome")
    filtro_email = st.sidebar.text_input("Email")
    filtro_faixa = st.sidebar.selectbox("Faixa etária", [None,"0-20","21-40","41-60","61+"])
    
    df = carregar_usuarios(filtro_nome, filtro_email, filtro_faixa)

    # --- Admin ---
    if st.session_state.role == "admin":
        with st.expander("Adicionar Usuário"):
            nome = st.text_input("Nome", key="nome_add")
            email = st.text_input("Email", key="email_add")
            idade = st.number_input("Idade", min_value=0, max_value=120, step=1, key="idade_add")
            if st.button("Adicionar Usuário"):
                if nome and email:
                    adicionar_usuario(nome,email,idade, st.session_state.user)
                    st.experimental_rerun()
                else:
                    st.error("Preencha todos os campos!")

        # CSV
        with st.expander("Importar/Exportar CSV"):
            uploaded_file = st.file_uploader("Importar CSV", type="csv")
            if uploaded_file:
                importar_csv(uploaded_file, st.session_state.user)
                st.experimental_rerun()
            if st.button("Exportar CSV"):
                exportar_csv(df)

    # --- Lista de usuários ---
    st.subheader("Lista de Usuários")
    if not df.empty:
        for _, row in df.iterrows():
            col1,col2,col3,col4,col5 = st.columns([1,2,2,1,1])
            col1.write(row.get('id'))
            col2.write(row.get('nome'))
            col3.write(row.get('email'))
            col4.write(row.get('idade'))

            if st.session_state.role == "admin":
                if col5.button("Deletar", key=f"del_{row.get('id')}"):
                    deletar_usuario(row.get('id'), st.session_state.user)
                    st.experimental_rerun()
    else:
        st.info("Nenhum usuário encontrado.")

    # --- Gráficos ---
    st.subheader("Gráficos Interativos")
    if not df.empty:
        fig1 = px.bar(df['idade'].value_counts().sort_index(), labels={'index':'Idade','value':'Quantidade'}, title="Distribuição de Idades")
        st.plotly_chart(fig1, use_container_width=True)

        bins = [0,20,40,60,120]; labels = ["0-20","21-40","41-60","61+"]
        df['faixa'] = pd.cut(df['idade'], bins=bins, labels=labels)
        fig2 = px.pie(df['faixa'].value_counts(), names=df['faixa'].value_counts().index, values=df['faixa'].value_counts().values, title="Proporção Faixas Etárias")
        st.plotly_chart(fig2, use_container_width=True)
else:
    st.warning("Faça login para acessar o dashboard.")
