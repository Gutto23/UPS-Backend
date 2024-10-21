const { config } = require("dotenv");
const mysql = require("mysql2/promise");
const UserModel = require("../model/User");
const bcrypt = require("bcryptjs");

config();

const clientDB = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DATABASE,
});

class UserController {
  /**
   * @description Obtém um usuário pelo ID
   */
  async getOneUser(req, res) {
    const userId = req.params.id;

    try {
      const [rows] = await clientDB.query("SELECT * FROM usuario WHERE idUsuario = ?", [userId]);
      if (rows.length === 0) {
        return res.status(404).json({ msg: "Usuário não encontrado" });
      }

      const user = rows[0];
      res.status(200).json(user);
    } catch (error) {
      res.status(500).json({ msg: "Erro ao buscar usuário" });
      console.error("Erro ao buscar usuário:", error);
    }
  }

  /**
   * @description Cria um novo usuário
   */
  async registroUsuario(req, res) {
    const { nomeUsuario, userUsuario, senhaUsuario, cpfUsuario, emailUsuario } = req.body;

    // Validação de campos obrigatórios
    if (!nomeUsuario || !userUsuario || !emailUsuario || !senhaUsuario || !cpfUsuario) {
      return res.status(422).json({ msg: "Todos os campos são obrigatórios!" });
    }

    try {
      // Verificar se o e-mail já está em uso
      const [rows] = await clientDB.query("SELECT * FROM usuario WHERE emailUsuario = ?", [emailUsuario]);
      if (rows.length > 0) {
        return res.status(422).json({ msg: "E-mail em uso! Por favor, utilize outro e-mail!" });
      }

      // Criação do hash da senha
      const salt = await bcrypt.genSalt(12);
      const passwordHash = await bcrypt.hash(senhaUsuario, salt);

      // Criação do objeto do novo usuário
      const novoUsuario = new UserModel(nomeUsuario, userUsuario, passwordHash, cpfUsuario, emailUsuario);

      // Inserção no banco de dados
      await clientDB.query("INSERT INTO usuario SET ?", novoUsuario);
      res.status(201).json({ msg: "Usuário criado com sucesso!" });
    } catch (error) {
      res.status(500).json({ msg: "Erro interno do servidor ao criar usuário" });
      console.error("Erro ao criar usuário:", error);
    }
  }

  /**
   * @description Atualiza um usuário existente pelo ID
   */
  async atualizarUsuario(req, res) {
    const userId = req.params.id;
    const { nomeUsuario, userUsuario, cpfUsuario, emailUsuario, senhaUsuario } = req.body;

    // Verificar se ao menos um dado foi fornecido para atualização
    if (!nomeUsuario && !userUsuario && !cpfUsuario && !emailUsuario && !senhaUsuario) {
      return res.status(422).json({ msg: "Nenhum dado fornecido para atualizar!" });
    }

    let updateFields = {};
    if (nomeUsuario) updateFields.nomeUsuario = nomeUsuario;
    if (userUsuario) updateFields.userUsuario = userUsuario;
    if (cpfUsuario) updateFields.cpfUsuario = cpfUsuario;
    if (emailUsuario) updateFields.emailUsuario = emailUsuario;

    // Se a senha foi fornecida, gerar um hash para a nova senha
    if (senhaUsuario) {
      const salt = await bcrypt.genSalt(12);
      const passwordHash = await bcrypt.hash(senhaUsuario, salt);
      updateFields.senhaUsuario = passwordHash;
    }

    try {
      const [result] = await clientDB.query("UPDATE usuario SET ? WHERE idUsuario = ?", [updateFields, userId]);
      if (result.affectedRows === 0) {
        return res.status(404).json({ msg: "Usuário não encontrado" });
      }

      res.status(200).json({ msg: "Usuário atualizado com sucesso!" });
    } catch (error) {
      res.status(500).json({ msg: "Erro interno do servidor ao atualizar usuário" });
      console.error("Erro ao atualizar usuário:", error);
    }
  }

  /**
   * @description Deleta um usuário existente pelo ID
   */
  async deletarUsuario(req, res) {
    const userId = req.params.id;

    try {
      const [result] = await clientDB.query("DELETE FROM usuario WHERE idUsuario = ?", [userId]);
      if (result.affectedRows === 0) {
        return res.status(404).json({ msg: "Usuário não encontrado" });
      }

      res.status(200).json({ msg: "Usuário deletado com sucesso!" });
    } catch (error) {
      res.status(500).json({ msg: "Erro interno do servidor ao deletar usuário" });
      console.error("Erro ao deletar usuário:", error);
    }
  }
}

module.exports = UserController;
