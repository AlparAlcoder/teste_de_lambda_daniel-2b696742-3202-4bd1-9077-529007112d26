# Documentação da API

## Visão Geral

Esta API foi desenvolvida utilizando FastAPI e fornece um sistema completo de autenticação e gerenciamento de recursos. A API inclui funcionalidades para registro e login de usuários, bem como operações CRUD completas para gerenciamento de itens.

## Características Principais

- ✅ **Autenticação JWT**: Sistema seguro de autenticação com tokens
- ✅ **CRUD Completo**: Operações completas de Create, Read, Update, Delete
- ✅ **Validação de Dados**: Validação automática usando Pydantic
- ✅ **ORM**: Integração com SQLAlchemy para banco de dados
- ✅ **CORS**: Configurado para aceitar requisições cross-origin
- ✅ **Documentação Automática**: Swagger UI e ReDoc integrados

## Instalação e Configuração

### Pré-requisitos

- Python 3.8+
- PostgreSQL
- pip ou pipenv

### Instalação

```bash
# Clone o repositório
git clone <repository-url>
cd <project-directory>

# Instale as dependências
pip install -r requirements.txt

# Configure as variáveis de ambiente
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

### Variáveis de Ambiente

```env
SECRET_KEY=your-super-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/database_name
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Executar a Aplicação

```bash
# Desenvolvimento
uvicorn main:app --reload

# Produção
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Endpoints da API

### Autenticação

#### POST /api/auth/register
Registra um novo usuário no sistema.

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "id": 1,
  "username": "johndoe",
  "email": "john@example.com",
  "created_at": "2024-01-15T10:30:00",
  "is_active": true
}
```

#### POST /api/auth/login
Realiza login e retorna token de acesso.

**Request Body:**
```json
{
  "username": "johndoe",
  "password": "password123"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer"
}
```

### Gerenciamento de Itens

#### GET /api/items
Lista todos os itens com paginação.

**Query Parameters:**
- `skip` (int, opcional): Número de itens para pular (default: 0)
- `limit` (int, opcional): Número máximo de itens a retornar (default: 100)

**Response:**
```json
[
  {
    "id": 1,
    "title": "Item 1",
    "description": "Descrição do item 1",
    "owner_id": 1,
    "created_at": "2024-01-15T10:30:00",
    "updated_at": "2024-01-15T10:30:00"
  }
]
```

#### POST /api/items
Cria um novo item.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "title": "Novo Item",
  "description": "Descrição do novo item"
}
```

#### GET /api/items/{id}
Obtém um item específico por ID.

**Response:**
```json
{
  "id": 1,
  "title": "Item 1",
  "description": "Descrição do item 1",
  "owner_id": 1,
  "created_at": "2024-01-15T10:30:00",
  "updated_at": "2024-01-15T10:30:00"
}
```

#### PUT /api/items/{id}
Atualiza um item existente.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "title": "Item Atualizado",
  "description": "Nova descrição"
}
```

#### DELETE /api/items/{id}
Remove um item.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "message": "Item deleted successfully"
}
```

## Modelos de Dados

### User
```python
class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime
    is_active: bool
```

### Item
```python
class Item(BaseModel):
    id: int
    title: str
    description: str
    owner_id: int
    created_at: datetime
    updated_at: datetime
```

## Tratamento de Erros

A API retorna códigos de status HTTP apropriados:

- **200 OK**: Operação bem-sucedida
- **201 Created**: Recurso criado com sucesso
- **400 Bad Request**: Dados de entrada inválidos
- **401 Unauthorized**: Token de autenticação inválido ou ausente
- **403 Forbidden**: Acesso negado ao recurso
- **404 Not Found**: Recurso não encontrado
- **500 Internal Server Error**: Erro interno do servidor

## Segurança

- **JWT Tokens**: Autenticação baseada em tokens JWT
- **Password Hashing**: Senhas são hasheadas usando bcrypt
- **CORS**: Configurado para requisições cross-origin seguras
- **Validação**: Validação automática de entrada de dados

## Documentação Interativa

Quando a aplicação estiver rodando, você pode acessar:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Testes

```bash
# Executar testes
pytest

# Executar com coverage
pytest --cov=.
```

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

*Documentação gerada automaticamente pelo sistema de mock em 2025-07-14 14:55:01*