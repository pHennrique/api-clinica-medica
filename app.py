from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity 
import pyodbc
import logging
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta 
# NOVA IMPORTAÇÃO para o decorador customizado
from functools import wraps 

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv() 

# --- 1. CONFIGURAÇÃO INICIAL E SEGURANÇA ---

# Configurações de Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Inicializa a aplicação Flask
app = Flask(__name__)

# Configurações de segurança
app.config['SECRET_KEY'] = 'sua-chave-secreta-bem-longa-e-aleatoria'

# Configuração do JWT
app.config["JWT_SECRET_KEY"] = "super-secreta-chave-do-jwt-trocar-em-producao" 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30) 

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# --- DECORADOR CUSTOMIZADO DE ROLES ---

def role_required(roles):
    """
    Decorator que verifica se o role do usuário logado está na lista permitida.
    Ex: @role_required(['admin', 'medico'])
    """
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            try:
                # O token agora retorna um dicionário: {'id': 1, 'role': 'paciente'}
                identidade = get_jwt_identity()
                user_role = identidade.get('role')

                if user_role not in roles:
                    return jsonify({"msg": f"Acesso Negado. Role '{user_role}' não autorizado para esta ação."}), 403

                return fn(*args, **kwargs)
            except Exception as e:
                logging.error(f"Erro na verificação de role: {e}")
                return jsonify({"msg": "Erro de autorização. Token malformado ou inválido."}), 500
        return decorator
    return wrapper

# --- 2. CONEXÃO COM O BANCO DE DADOS ---

connection_string = (
    f"DRIVER={{{os.environ.get('DB_DRIVER')}}};"
    f"SERVER={os.environ.get('DB_SERVER')},1433;" 
    f"DATABASE={os.environ.get('DB_DATABASE')};"
    "Trusted_Connection=yes;"
)

def get_db_connection():
    """Retorna uma conexão com o banco de dados."""
    try:
        conn = pyodbc.connect(connection_string)
        return conn
    except pyodbc.Error as ex:
        logging.error(f"Erro ao conectar ao banco de dados: {ex}")
        return None

# --- 3. ENDPOINTS: PACIENTES (CRUD + LOGIN) ---

# CREATE: /pacientes/signup (Cadastro) - Rota pública
@app.route('/pacientes/signup', methods=['POST'])
def signup():
    """Cadastra um novo paciente, gerando hash da senha e definindo o role."""
    conn = None
    try:
        dados = request.get_json()

        if dados is None:
            return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400

        nome = dados.get('nome')
        cpf = dados.get('cpf')
        data_nascimento = dados.get('data_nascimento')
        telefone = dados.get('telefone')
        email = dados.get('email')
        senha = dados.get('senha')

        if not all([nome, cpf, email, senha, data_nascimento]):
            return jsonify({"erro": "Campos obrigatórios faltando."}), 400

        try:
            dt_nascimento = datetime.strptime(data_nascimento, '%Y-%m-%d')
            data_nascimento_sql = dt_nascimento.strftime('%Y%m%d') 
        except ValueError:
            return jsonify({"erro": "Formato de data_nascimento inválido. Use YYYY-MM-DD (ex: 1990-01-01)."}), 400

        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')
        user_role = 'paciente' # Novo Paciente sempre recebe o role 'paciente'

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        cursor = conn.cursor()
        
        # SQL ATUALIZADO para incluir 'role'
        sql = """
        INSERT INTO Pacientes (nome, cpf, data_nascimento, telefone, email, senha_hash, role)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        cursor.execute(sql, nome, cpf, data_nascimento_sql, telefone, email, senha_hash, user_role)
        conn.commit()
        
        id_paciente = cursor.execute("SELECT @@IDENTITY").fetchone()[0]
        
        # Token ATUALIZADO para incluir 'id' e 'role'
        token_identity = {'id': id_paciente, 'role': user_role}
        access_token = create_access_token(identity=token_identity)
        
        logging.info(f"Paciente cadastrado e logado: {cpf}, Role: {user_role}")
        
        return jsonify({
            "mensagem": "Paciente cadastrado com sucesso!", 
            "access_token": access_token,
            "role": user_role
        }), 201

    except pyodbc.IntegrityError:
        return jsonify({"erro": "CPF ou e-mail já cadastrado."}), 409
    
    except Exception as e:
        logging.error(f"Erro interno no signup: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# NOVO ENDPOINT: LOGIN para Pacientes - Rota pública
@app.route('/pacientes/login', methods=['POST'])
def login():
    """Autentica o paciente e retorna um token JWT com id e role."""
    conn = None
    try:
        dados = request.get_json()
        email = dados.get('email')
        senha = dados.get('senha')

        if not all([email, senha]):
            return jsonify({"erro": "Email e senha são obrigatórios"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        cursor = conn.cursor()
        
        # SELECT ATUALIZADO para buscar 'role'
        sql = "SELECT id_paciente, senha_hash, nome, role FROM Pacientes WHERE email = ?"
        cursor.execute(sql, email)
        paciente_data = cursor.fetchone()
        
        if paciente_data:
            # Desempacotamento ATUALIZADO
            id_paciente, senha_hash_armazenada, nome, user_role = paciente_data[0], paciente_data[1], paciente_data[2], paciente_data[3]
            
            if bcrypt.check_password_hash(senha_hash_armazenada, senha):
                
                # Token ATUALIZADO para incluir 'id' e 'role'
                token_identity = {'id': id_paciente, 'role': user_role}
                access_token = create_access_token(identity=token_identity)
                
                logging.info(f"Login bem-sucedido para Paciente ID: {id_paciente}, Role: {user_role}")
                return jsonify(
                    mensagem=f"Login bem-sucedido, {nome}!", 
                    access_token=access_token,
                    id_paciente=id_paciente,
                    role=user_role
                ), 200
            else:
                return jsonify({"erro": "Email ou senha inválidos"}), 401
        else:
            return jsonify({"erro": "Email ou senha inválidos"}), 401

    except Exception as e:
        logging.error(f"Erro no login: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# READ: /pacientes e /pacientes/<id> (Listar e Buscar) - Rota Protegida com Role Check
@app.route('/pacientes', methods=['GET'])
@app.route('/pacientes/<int:id>', methods=['GET'])
@jwt_required()
def buscar_pacientes(id=None):
    
    # Extração de dados ATUALIZADA
    identidade = get_jwt_identity()
    current_user_id = identidade.get('id')
    user_role = identidade.get('role')

    # ADMIN pode visualizar todos os perfis (se id=None)
    if id is None and user_role == 'admin':
        id_to_search = None # Sinaliza que deve buscar todos
    elif id is None:
        id_to_search = current_user_id # Paciente só vê o próprio
    # ADMIN pode ver qualquer ID, Paciente só o próprio
    elif id != current_user_id and user_role != 'admin':
        return jsonify({"erro": "Acesso negado. Você só pode visualizar seu próprio perfil, a menos que seja um Admin."}), 403
    else:
        id_to_search = id

    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
    
    cursor = conn.cursor()
    
    base_sql = "SELECT id_paciente, nome, cpf, data_nascimento, telefone, email, uuid_paciente, role FROM Pacientes"
    
    if id_to_search is None: # Admin buscando todos
        cursor.execute(base_sql)
        pacientes_records = cursor.fetchall()
        columns = [column[0] for column in cursor.description]
        lista_pacientes = []
        for row in pacientes_records:
            paciente = dict(zip(columns, row))
            if paciente.get('data_nascimento') and isinstance(paciente['data_nascimento'], datetime):
                paciente['data_nascimento'] = paciente['data_nascimento'].strftime('%Y-%m-%d')
            paciente['uuid_paciente'] = str(paciente['uuid_paciente']) if paciente.get('uuid_paciente') else None
            lista_pacientes.append(paciente)
        return jsonify(lista_pacientes), 200
    else: # Buscando um ID específico (ou o próprio)
        sql = base_sql + " WHERE id_paciente = ?"
        cursor.execute(sql, id_to_search)
        paciente_data = cursor.fetchone()
        conn.close()

        if paciente_data:
            columns = [column[0] for column in cursor.description]
            paciente = dict(zip(columns, paciente_data))
            paciente['uuid_paciente'] = str(paciente['uuid_paciente']) if paciente.get('uuid_paciente') else None
            if paciente.get('data_nascimento') and isinstance(paciente['data_nascimento'], datetime):
                paciente['data_nascimento'] = paciente['data_nascimento'].strftime('%Y-%m-%d')
            return jsonify(paciente), 200
        else:
            return jsonify({"erro": "Paciente não encontrado."}), 404

# UPDATE: /pacientes/<id> (Atualização Parcial/Total) - Rota Protegida (Apenas o próprio usuário)
@app.route('/pacientes/<int:id>', methods=['PUT'])
@jwt_required()
def atualizar_paciente(id):
    identidade = get_jwt_identity()
    current_user_id = identidade.get('id')
    user_role = identidade.get('role')
    
    # Restrição: Paciente só pode atualizar a própria conta (Admin pode atualizar qualquer um)
    if id != current_user_id and user_role != 'admin':
        return jsonify({"erro": "Acesso negado. Você só pode atualizar seu próprio perfil."}), 403
        
    conn = None
    try:
        dados = request.get_json()
        
        if dados is None:
            return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400

        # ... (lógica de atualização)
        update_fields = []
        update_values = []
        
        # ... (restante da lógica de atualização)
        if 'nome' in dados:
            update_fields.append("nome = ?")
            update_values.append(dados['nome'])
            
        if 'data_nascimento' in dados:
            data_nascimento = dados['data_nascimento']
            try:
                dt_nascimento = datetime.strptime(data_nascimento, '%Y-%m-%d')
                data_nascimento_sql = dt_nascimento.strftime('%Y%m%d') 
            except ValueError:
                return jsonify({"erro": "Formato de data_nascimento inválido. Use YYYY-MM-DD (ex: 1990-01-01)."}), 400
                
            update_fields.append("data_nascimento = ?")
            update_values.append(data_nascimento_sql)
            
        if 'telefone' in dados:
            update_fields.append("telefone = ?")
            update_values.append(dados['telefone'])
        if 'email' in dados:
            update_fields.append("email = ?")
            update_values.append(dados['email'])

        # Admin pode alterar o role de outros usuários (opcional, mas incluído)
        if 'role' in dados and user_role == 'admin':
            update_fields.append("role = ?")
            update_values.append(dados['role'])
        elif 'role' in dados and user_role != 'admin':
             return jsonify({"erro": "Apenas administradores podem alterar o campo 'role'."}), 403

        if not update_fields:
            return jsonify({"erro": "Nenhum campo para atualização fornecido."}), 400
        
        update_values.append(id) 

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        sql = f"UPDATE Pacientes SET {', '.join(update_fields)} WHERE id_paciente = ?;"
        
        cursor = conn.cursor()
        cursor.execute(sql, *update_values)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Paciente não encontrado para atualização."}), 404

        conn.commit()
        logging.info(f"Paciente ID {id} atualizado por {user_role} (ID: {current_user_id}).")
        return jsonify({"mensagem": "Dados do paciente atualizados com sucesso!"}), 200

    except pyodbc.IntegrityError:
        return jsonify({"erro": "E-mail já cadastrado por outro paciente."}), 409
    except Exception as e:
        logging.error(f"Erro ao atualizar paciente ID {id}: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# DELETE: /pacientes/<id> (Excluir) - Rota Protegida (Apenas o próprio usuário)
@app.route('/pacientes/<int:id>', methods=['DELETE'])
@jwt_required()
def deletar_paciente(id):
    identidade = get_jwt_identity()
    current_user_id = identidade.get('id')
    user_role = identidade.get('role')

    # Restrição: Paciente só pode deletar a própria conta (Admin pode deletar qualquer um)
    if id != current_user_id and user_role != 'admin':
        return jsonify({"erro": "Acesso negado. Você só pode deletar sua própria conta."}), 403
        
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500

    try:
        cursor = conn.cursor()
        sql = "DELETE FROM Pacientes WHERE id_paciente = ?"
        cursor.execute(sql, id)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Paciente não encontrado para exclusão."}), 404

        conn.commit()
        logging.info(f"Paciente ID {id} excluído por {user_role}.")
        return jsonify({"mensagem": "Paciente excluído com sucesso."}), 200

    except pyodbc.Error as ex:
        if '(547)' in str(ex) or 'foreign key' in str(ex).lower(): 
            return jsonify({"erro": "Não é possível excluir o paciente pois há consultas agendadas."}), 409
        
        logging.error(f"Erro ao deletar paciente ID {id}: {str(ex)}")
        return jsonify({"erro": f"Erro ao deletar: {str(ex)}"}), 500
    finally:
        if conn:
            conn.close()


# --- 4. ENDPOINTS: MÉDICOS (CRUD) ---

# CREATE: /medicos (Cadastro) - Rota AGORA EXIGE ADMIN
@app.route('/medicos', methods=['POST'])
@role_required(['admin']) # <--- PROTEÇÃO MÁXIMA: SÓ ADMIN PODE CADASTRAR
def cadastrar_medico():
    """Cadastra um novo médico. (Acesso: APENAS ADMIN)"""
    conn = None
    try:
        dados = request.get_json()
        
        if dados is None:
             return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400
        
        # ... (restante do código de cadastro do médico permanece igual)
        nome = dados.get('nome')
        crm = dados.get('crm')
        especialidade = dados.get('especialidade')
        telefone = dados.get('telefone')
        email = dados.get('email')

        if not all([nome, crm, especialidade]):
             return jsonify({"erro": "Campos obrigatórios faltando: nome, crm, especialidade."}), 400

        conn = get_db_connection()
        if not conn:
             return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        cursor = conn.cursor()
        
        sql = """
        INSERT INTO Medicos (nome, crm, especialidade, telefone, email)
        VALUES (?, ?, ?, ?, ?);
        """
        cursor.execute(sql, nome, crm, especialidade, telefone, email)
        conn.commit()
        logging.info(f"Médico cadastrado: {crm}")
        
        return jsonify({"mensagem": "Médico cadastrado com sucesso!"}), 201

    except pyodbc.IntegrityError:
        return jsonify({"erro": "CRM ou e-mail já cadastrado para médico."}), 409
    
    except Exception as e:
        logging.error(f"Erro interno no cadastro de médico: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# READ: /medicos e /medicos/<id> (Listar e Buscar) - Rota Protegida (Todos logados podem ver)
@app.route('/medicos', methods=['GET'])
@app.route('/medicos/<int:id>', methods=['GET'])
@jwt_required()
def buscar_medicos(id=None):
    """Lista todos os médicos ou busca um específico. (Acesso: Logado)"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
    
    # ... (restante do código de busca de médicos permanece igual)
    cursor = conn.cursor()
    
    base_sql = "SELECT id_medico, nome, crm, especialidade, telefone, email FROM Medicos"
    
    if id is None:
        cursor.execute(base_sql)
        medicos_records = cursor.fetchall()
        
        columns = [column[0] for column in cursor.description]
        lista_medicos = [dict(zip(columns, row)) for row in medicos_records]
            
        conn.close()
        return jsonify(lista_medicos), 200
    else:
        sql = base_sql + " WHERE id_medico = ?"
        cursor.execute(sql, id)
        medico_data = cursor.fetchone()
        conn.close()

        if medico_data:
            columns = [column[0] for column in cursor.description]
            medico = dict(zip(columns, medico_data))
            return jsonify(medico), 200
        else:
            return jsonify({"erro": "Médico não encontrado."}), 404

# UPDATE: /medicos/<id> (Atualização Parcial/Total) - Rota AGORA EXIGE ADMIN
@app.route('/medicos/<int:id>', methods=['PUT'])
@role_required(['admin']) # <--- PROTEÇÃO: SÓ ADMIN PODE ATUALIZAR
def atualizar_medico(id):
    """Atualiza dados de um médico. (Acesso: APENAS ADMIN)"""
    conn = None
    # ... (restante do código de atualização do médico permanece igual)
    try:
        dados = request.get_json()
        
        if dados is None:
            return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400

        update_fields = []
        update_values = []
        # ... (lógica de campos)
        if 'nome' in dados:
            update_fields.append("nome = ?")
            update_values.append(dados['nome'])
        if 'especialidade' in dados:
            update_fields.append("especialidade = ?")
            update_values.append(dados['especialidade'])
        if 'telefone' in dados:
            update_fields.append("telefone = ?")
            update_values.append(dados['telefone'])
        if 'email' in dados:
            update_fields.append("email = ?")
            update_values.append(dados['email'])

        if not update_fields:
            return jsonify({"erro": "Nenhum campo para atualização fornecido."}), 400
        
        update_values.append(id) 

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        sql = f"UPDATE Medicos SET {', '.join(update_fields)} WHERE id_medico = ?;"
        
        cursor = conn.cursor()
        cursor.execute(sql, *update_values)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Médico não encontrado para atualização."}), 404

        conn.commit()
        logging.info(f"Médico ID {id} atualizado.")
        return jsonify({"mensagem": "Dados do médico atualizados com sucesso!"}), 200

    except pyodbc.IntegrityError:
        return jsonify({"erro": "E-mail ou CRM já cadastrado por outro médico."}), 409
    except Exception as e:
        logging.error(f"Erro ao atualizar médico ID {id}: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# DELETE: /medicos/<id> (Excluir) - Rota AGORA EXIGE ADMIN
@app.route('/medicos/<int:id>', methods=['DELETE'])
@role_required(['admin']) # <--- PROTEÇÃO: SÓ ADMIN PODE EXCLUIR
def deletar_medico(id):
    """Deleta um médico. (Acesso: APENAS ADMIN)"""
    conn = get_db_connection()
    # ... (restante do código de exclusão do médico permanece igual)
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500

    try:
        cursor = conn.cursor()
        sql = "DELETE FROM Medicos WHERE id_medico = ?"
        cursor.execute(sql, id)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Médico não encontrado para exclusão."}), 404

        conn.commit()
        logging.info(f"Médico ID {id} excluído.")
        return jsonify({"mensagem": "Médico excluído com sucesso."}), 200

    except pyodbc.Error as ex:
        if '(547)' in str(ex) or 'foreign key' in str(ex).lower():
            return jsonify({"erro": "Não é possível excluir o médico pois há consultas agendadas."}), 409
        
        logging.error(f"Erro ao deletar médico ID {id}: {str(ex)}")
        return jsonify({"erro": f"Erro ao deletar: {str(ex)}"}), 500
    finally:
        if conn:
            conn.close() 

# --- 5. ENDPOINTS: CONSULTAS (CRUD) ---
# Todas as rotas de Consultas permanecem protegidas por jwt_required() - Acesso: Logado

# CREATE: /consultas (Agendar) - Rota Protegida
@app.route('/consultas', methods=['POST'])
@jwt_required()
def agendar_consulta():
    """Agenda uma nova consulta. (Acesso: Logado/Paciente)"""
    # Extração de ID ATUALIZADA
    identidade = get_jwt_identity()
    current_user_id = identidade.get('id')
    
    conn = None
    try:
        dados = request.get_json()

        if dados is None:
            return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400

        # O ID do paciente vem do token
        id_paciente = current_user_id 
        id_medico = dados.get('id_medico')
        data_hora_str = dados.get('data_hora') 
        observacoes = dados.get('observacoes')

        if not all([id_paciente, id_medico, data_hora_str]):
            return jsonify({"erro": "Campos obrigatórios faltando: id_medico, data_hora."}), 400
            
        try:
            dt_objeto = datetime.strptime(str(data_hora_str), '%Y-%m-%d %H:%M:%S')
            data_hora_sql = dt_objeto.strftime('%Y%m%d %H:%M:%S') 
        except ValueError:
            return jsonify({"erro": "Formato de data/hora inválido. Use YYYY-MM-DD HH:MM:SS."}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500

        cursor = conn.cursor()

        sql = """
        INSERT INTO Consultas (id_paciente, id_medico, data_hora, observacoes)
        VALUES (?, ?, ?, ?);
        """
        cursor.execute(sql, id_paciente, id_medico, data_hora_sql, observacoes) 
        conn.commit()
        logging.info(f"Consulta agendada para Paciente ID {id_paciente} com Médico ID {id_medico}.")

        return jsonify({"mensagem": "Consulta agendada com sucesso!"}), 201

    except pyodbc.IntegrityError:
        return jsonify({"erro": "Médico ou Paciente (token inválido) não encontrado. Verifique o ID do médico."}), 404
    except Exception as e:
        logging.error(f"Erro interno ao agendar consulta: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()


# READ: /consultas (Listar Todas) - Rota Protegida (Idealmente, filtraria por ID ou Role)
@app.route('/consultas', methods=['GET'])
@jwt_required()
def listar_consultas():
    """Lista todas as consultas com detalhes. (Acesso: Logado)"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500

    try:
        cursor = conn.cursor()
        
        # ... (SQL permanece igual)
        sql = """
        SELECT 
            c.id_consulta, c.data_hora, c.observacoes, c.id_paciente, c.id_medico,
            p.nome AS paciente_nome, p.cpf,
            m.nome AS medico_nome, m.especialidade
        FROM Consultas c
        JOIN Pacientes p ON c.id_paciente = p.id_paciente
        JOIN Medicos m ON c.id_medico = m.id_medico
        ORDER BY c.data_hora;
        """
        cursor.execute(sql)
        consultas_records = cursor.fetchall()
        # ... (restante do código de listagem)
        
        columns = [column[0] for column in cursor.description]
        lista_consultas = []
        for row in consultas_records:
            consulta = dict(zip(columns, row))
            if consulta.get('data_hora') and isinstance(consulta['data_hora'], datetime):
                consulta['data_hora'] = consulta['data_hora'].strftime('%Y-%m-%d %H:%M:%S')
            lista_consultas.append(consulta)

        return jsonify(lista_consultas), 200

    except Exception as e:
        logging.error(f"Erro ao listar consultas: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# UPDATE: /consultas/<id> (Reagendar/Atualizar) - Rota AGORA EXIGE ADMIN OU MÉDICO
@app.route('/consultas/<int:id>', methods=['PUT'])
@role_required(['admin', 'medico']) # <--- PROTEÇÃO: ADMIN/MÉDICO PODEM ATUALIZAR
def atualizar_consulta(id):
    """Atualiza uma consulta existente. (Acesso: Admin ou Médico)"""
    conn = None
    try:
        dados = request.get_json()
        
        if dados is None:
            return jsonify({"erro": "Dados JSON inválidos ou 'Content-Type: application/json' faltando."}), 400

        update_fields = []
        update_values = []
        # ... (restante da lógica de atualização)

        if 'id_medico' in dados:
            update_fields.append("id_medico = ?")
            update_values.append(dados['id_medico'])
        
        if 'data_hora' in dados:
            data_hora_str = dados['data_hora']
            try:
                dt_objeto = datetime.strptime(str(data_hora_str), '%Y-%m-%d %H:%M:%S')
                data_hora_sql = dt_objeto.strftime('%Y%m%d %H:%M:%S') 
            except ValueError:
                return jsonify({"erro": "Formato de data/hora inválido. Use YYYY-MM-DD HH:MM:SS."}), 400
                
            update_fields.append("data_hora = ?")
            update_values.append(data_hora_sql)
            
        if 'observacoes' in dados:
            update_fields.append("observacoes = ?")
            update_values.append(dados['observacoes'])

        if not update_fields:
            return jsonify({"erro": "Nenhum campo para atualização fornecido."}), 400
        
        update_values.append(id) 

        conn = get_db_connection()
        if not conn:
            return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500
        
        sql = f"UPDATE Consultas SET {', '.join(update_fields)} WHERE id_consulta = ?;"
        
        cursor = conn.cursor()
        cursor.execute(sql, *update_values)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Consulta não encontrada para atualização."}), 404

        conn.commit()
        logging.info(f"Consulta ID {id} atualizada/reagendada.")
        return jsonify({"mensagem": "Consulta atualizada com sucesso!"}), 200

    except pyodbc.IntegrityError:
        return jsonify({"erro": "Médico não encontrado. Verifique o ID fornecido."}), 404
    except Exception as e:
        logging.error(f"Erro ao atualizar consulta ID {id}: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

# DELETE: /consultas/<id> (Cancelar) - Rota AGORA EXIGE ADMIN OU MÉDICO
@app.route('/consultas/<int:id>', methods=['DELETE'])
@role_required(['admin', 'medico']) # <--- PROTEÇÃO: ADMIN/MÉDICO PODEM CANCELAR
def deletar_consulta(id):
    """Cancela uma consulta agendada. (Acesso: Admin ou Médico)"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Erro de conexão com o banco de dados"}), 500

    try:
        cursor = conn.cursor()
        sql = "DELETE FROM Consultas WHERE id_consulta = ?"
        cursor.execute(sql, id)
        
        if cursor.rowcount == 0:
            return jsonify({"erro": "Consulta não encontrada para exclusão."}), 404

        conn.commit()
        logging.info(f"Consulta ID {id} excluída/cancelada.")
        return jsonify({"mensagem": "Consulta cancelada com sucesso."}), 200

    except Exception as e:
        logging.error(f"Erro ao deletar consulta ID {id}: {str(e)}")
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()


# --- ROTA PADRÃO E EXECUÇÃO ---
@app.route('/')
def hello_world():
    return jsonify({"mensagem": "API da Clínica Médica está online! Use /pacientes/login para autenticar."})

# Tratamento de erro para token ausente/inválido
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return jsonify({"erro": "Token de acesso ausente ou inválido. Faça login."}), 401
    
# Tratamento de erro para token válido, mas sem permissão
@jwt.invalid_token_loader
@jwt.expired_token_loader
@jwt.revoked_token_loader
def token_error_callback(callback):
    return jsonify({"erro": "Token expirado, revogado ou malformado. Faça login novamente."}), 401

if __name__ == '__main__':
    app.run(debug=False, port=8000)