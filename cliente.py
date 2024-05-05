import time
#from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from servidor import Servidor

class Cliente:
    def __init__(self):
        self.__clientes = []
        self.servidor = Servidor()
    
    @property
    def clientes(self):
        return self.__clientes

    def cadastrar_cliente(self):
        login = input('Digite nome de usuário:')
        senha = input('Digite a senha:')
        chave = self.realizar_pbkdf(senha)
        self.servidor.cadastrar_cliente(login, chave)
        print('Usuário cadastrado com sucesso!')

    def realizar_login(self):
        login = input('Digite nome de usuário:')
        senha = input('Digite a senha:')
        chave = self.realizar_pbkdf(senha)
        existe_usuario = self.servidor.buscar_cliente(login, chave)
        if existe_usuario is False:
            print('cliente não encontrado')
            return
        #fazer o 2fa
        print('login realizado')

    def realizar_pbkdf(self, senha):
        salt = 'madonna'
        chave = PBKDF2(senha, salt, count=1000, hmac_hash_module=SHA512)
        return chave
