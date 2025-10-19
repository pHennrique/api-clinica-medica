-- Garante que o banco de dados 'clinica_medica' está selecionado
USE [clinica_medica];
GO

----------------------------------------------------
-- 1. Tabela Pacientes
-- A tabela que seu endpoint POST /pacientes/signup utiliza
----------------------------------------------------
IF OBJECT_ID('Pacientes', 'U') IS NOT NULL
    DROP TABLE Pacientes;
GO

CREATE TABLE Pacientes (
    id_paciente INT IDENTITY(1,1) PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    cpf VARCHAR(14) NOT NULL UNIQUE, -- CPF é único
    data_nascimento DATE,
    telefone VARCHAR(20),
    email VARCHAR(100) NOT NULL UNIQUE, -- E-mail é único
    senha_hash VARCHAR(255) NOT NULL, -- Armazena o hash da senha
    uuid_paciente UNIQUEIDENTIFIER DEFAULT NEWSEQUENTIALID() -- Usado para identificação segura
);
GO

----------------------------------------------------
-- 2. Tabela Medicos
----------------------------------------------------
IF OBJECT_ID('Medicos', 'U') IS NOT NULL
    DROP TABLE Medicos;
GO

CREATE TABLE Medicos (
    id_medico INT IDENTITY(1,1) PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    crm VARCHAR(20) NOT NULL UNIQUE, -- CRM é único
    especialidade VARCHAR(50) NOT NULL,
    telefone VARCHAR(20),
    email VARCHAR(100) NOT NULL UNIQUE
);
GO

----------------------------------------------------
-- 3. Tabela Consultas (Relacionamento N:M através de FKs)
----------------------------------------------------
IF OBJECT_ID('Consultas', 'U') IS NOT NULL
    DROP TABLE Consultas;
GO

CREATE TABLE Consultas (
    id_consulta INT IDENTITY(1,1) PRIMARY KEY,
    
    -- Chaves Estrangeiras (Foreign Keys)
    id_paciente INT NOT NULL,
    id_medico INT NOT NULL,
    
    data_hora DATETIME NOT NULL,
    observacoes TEXT,
    
    -- Restrições de Chave Estrangeira
    CONSTRAINT FK_Consulta_Paciente FOREIGN KEY (id_paciente)
        REFERENCES Pacientes (id_paciente),
        
    CONSTRAINT FK_Consulta_Medico FOREIGN KEY (id_medico)
        REFERENCES Medicos (id_medico)
);
GO