const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = 'chave_super_secreta_lab_docker'; // Em produção, usar variáveis de ambiente

const db = mysql.createConnection({
  host: 'mysql',
  user: 'user',
  password: 'user123',
  database: 'lab_db'
});

db.connect(err => {
  if (err) return console.error('Erro ao conectar:', err);
  console.log('Conectado ao MySQL!');
});


const verificarToken = (req, res, next) => {
  const tokenHeader = req.headers['authorization'];
  if (!tokenHeader) return res.status(403).json({ message: 'Token de autenticação não fornecido.' });

  const token = tokenHeader.split(' ')[1]; // Extrai do padrão "Bearer <token>"
  
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token inválido ou expirado.' });
    req.usuarioId = decoded.id; // Salva o ID logado na requisição
    next(); // Permite que a requisição continue
  });
};

// Rota de Login
app.post('/login', (req, res) => {
  const { email, senha } = req.body;
  
  db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ message: 'Credenciais inválidas' });

    const usuario = results[0];
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) return res.status(401).json({ message: 'Credenciais inválidas' });

    // Gera o token válido por 1 hora
    const token = jwt.sign({ id: usuario.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login bem-sucedido!', token });
  });
});

// Criar Usuário (Qualquer pessoa pode se cadastrar)
app.post('/usuarios', async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ error: 'Dados incompletos' });

  try {
    const hashSenha = await bcrypt.hash(senha, 10);
    const query = 'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)';
    
    db.query(query, [nome, email, hashSenha], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ message: 'Usuário criado com sucesso!', id: results.insertId });
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno ao processar a senha' });
  }
});

app.get('/usuarios', verificarToken, (req, res) => {
  db.query('SELECT id, nome, email, criado_em FROM usuarios', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.put('/usuarios/:id', verificarToken, (req, res) => {
  const { id } = req.params;
  const { nome, email } = req.body;
  
  const query = 'UPDATE usuarios SET nome = ?, email = ? WHERE id = ?';
  db.query(query, [nome, email, id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.affectedRows === 0) return res.status(404).json({ message: 'Usuário não encontrado' });
    res.json({ message: 'Usuário atualizado com sucesso!' });
  });
});

app.delete('/usuarios/:id', verificarToken, (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM usuarios WHERE id = ?';
  
  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.affectedRows === 0) return res.status(404).json({ message: 'Usuário não encontrado' });
    res.json({ message: 'Usuário removido com sucesso!' });
  });
});

app.listen(3000, () => {
  console.log('API rodando na porta 3000 com Autenticação JWT');
});