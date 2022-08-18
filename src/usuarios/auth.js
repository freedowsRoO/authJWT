const passport = require('passport');
const Usuario = require('./usuarios-modelo');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { InvalidArgumentError } = require('../erros');
const BearerStrategy = require('passport-http-bearer');
const blackList = require('../../redis/manipula-blacklist')

function verificaUsuario(usuario) {
    if (!usuario) {
        throw new InvalidArgumentError('Não existe usário com esse email');
    }
}

async function  verificaSenha(senha, senhaHash) {
   const senhaValida = await bcrypt.compare(senha,senhaHash);   

   if (!senhaValida) {
       throw new InvalidArgumentError('senha invalida');
   }
}

async function verificaTokenBlacklist(token) {
   const tokenResult = await blackList.contemToken(token);
   if (tokenResult) {
       throw new jwt.JsonWebTokenError('Token inválido por logout');
   }
}

passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'senha',
        session: false
    }, async (email, senha, done) => {        
        try {
            const usuario = await Usuario.buscaPorEmail(email);
            verificaUsuario(usuario);
            await verificaSenha(senha, usuario.senhaHash);
            done(null, usuario)
        } catch (error) {
            done(error);            
        }        
    })
)

passport.use(
    new BearerStrategy( async (token, done) => {
        try {
            await verificaTokenBlacklist(token);
            const payload = jwt.verify(token, process.env.CHAVE_JWT);
            const usuario = await Usuario.buscaPorId(payload.id);
            done(null, usuario, {token: token});
        } catch (error) {
            done(error);            
        }      
    })
)