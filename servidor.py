from Crypto.Protocol.KDF import scrypt

class Servidor:
    def __init__(self) -> None:
        self.__clientes = {}

    @property
    def clientes(self):
        return self.__clientes
    
    def cadastrar_cliente(self, login, chave):
        chave_scrypt = self.realizar_scrypt(chave)
        self.clientes[login] = chave_scrypt
    
    def buscar_cliente(self, login, chave):
        chave_scrypt = self.realizar_scrypt(chave)
        if (login, chave_scrypt) in self.clientes.items():
            return True
        return False
    
    def realizar_scrypt(self, chave):
        salt = 'madonna'
        chave_scrypt = scrypt(chave, salt, 16, N=2**14, r=8, p=1)
        return chave_scrypt
    
    #fazer login com 2fa