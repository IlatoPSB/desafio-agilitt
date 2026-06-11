
const session = require('express-session');
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
app.use(session({
    secret: 'meu-segredo-super-secreto',
    resave: false,
    saveUninitialized: false
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render('register');
});
app.post('/register', async (req, res) => {

    const { nome, email, senha } = req.body;

    try {

        const senhaCriptografada = await bcrypt.hash(senha, 10);

        const sql = `
            INSERT INTO usuarios (nome, email, senha)
            VALUES (?, ?, ?)
        `;

        db.query(
            sql,
            [nome, email, senhaCriptografada],
            (err, result) => {

                if (err) {
                    console.error(err);
                    return res.send('Erro ao cadastrar usuário.');
                }

                res.send('Usuário cadastrado com sucesso!');
            }
        );

    } catch (error) {
        console.error(error);
        res.send('Erro interno.');
    }

});
app.get('/login', (req, res) => {
    res.render('login');
});
app.post('/login', (req, res) => {

    const { email, senha } = req.body;

    const sql = 'SELECT * FROM usuarios WHERE email = ?';

    db.query(sql, [email], async (err, results) => {

        if (err) {
            console.error(err);
            return res.send('Erro ao fazer login.');
        }

        if (results.length === 0) {
            return res.send('Usuário não encontrado.');
        }

        const usuario = results[0];

        const senhaCorreta = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaCorreta) {
    return res.send('Senha incorreta.');
}

req.session.usuario = {
    id: usuario.id,
    nome: usuario.nome,
    email: usuario.email
};

res.redirect('/dashboard');
    });

});
app.get('/dashboard', (req, res) => {

    if (!req.session.usuario) {
        return res.redirect('/login');
    }

    res.render('dashboard', {
        usuario: req.session.usuario
    });

});
app.get('/logout', (req, res) => {

    req.session.destroy(() => {
        res.redirect('/login');
    });

});
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
