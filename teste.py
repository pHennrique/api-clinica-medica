import os
import pyodbc
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- Variáveis de Conexão ---
# Usamos a configuração mais robusta: SQL Server e porta TCP/IP 1433
# E autenticação do Windows (já que a do sa falhou)
DRIVER = os.getenv('DB_DRIVER', 'SQL Server')
SERVER = os.getenv('DB_SERVER', 'BOOK-ENOSCT59NK,1433')
DATABASE = os.getenv('DB_DATABASE', 'clinica_medica')

# --- String de Conexão (Autenticação do Windows) ---
# Se os valores de UID e PWD estiverem vazios no .env, pyodbc usa a conta do Windows
CONNECTION_STRING = (
    f'DRIVER={{{DRIVER}}};'
    f'SERVER={SERVER};'
    f'DATABASE={DATABASE};'
    'Trusted_Connection=yes;' # Define a conexão como confiável (Windows)
)

print("-" * 50)
print("Tentando Conectar ao SQL Server...")
print(f"Server: {SERVER}")
print(f"Database: {DATABASE}")
print("-" * 50)

# --- Teste de Conexão ---
try:
    # A linha que costuma falhar
    conexao = pyodbc.connect(CONNECTION_STRING)
    print("✅ Conectado ao banco de dados com sucesso!")
    conexao.close()

except pyodbc.Error as ex:
    # Captura e imprime o erro exato do pyodbc
    print("❌ Erro ao conectar ao banco de dados!")
    sqlstate = ex.args[0]
    if sqlstate == 'IM002':
        print("   -> Erro: Driver ODBC não encontrado ou nome incorreto no .env.")
    else:
        print(f"   -> Detalhes do Erro pyodbc: {ex}")