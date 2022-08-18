const usuariosControlador = require('./usuarios-controlador');
const middlewaresAuth = require('./middleware-auth');
const passport = require('passport');

module.exports = app => {
  app.route('/usuario/login')
  .post(middlewaresAuth.local, usuariosControlador.login);

  app.route('/usuario/logout')
  .get(middlewaresAuth.bearer, usuariosControlador.logout);

  app
    .route('/usuario')
    .post(usuariosControlador.adiciona)
    .get(usuariosControlador.lista);

  app.route('/usuario/:id')
  .delete(passport.authenticate('bearer', { session: false }), usuariosControlador.deleta);
};
