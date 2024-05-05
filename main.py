#pip install pycryptodome
#pip install qrcode
from cliente import Cliente
from servidor import Servidor

cliente = Cliente()

if __name__ == "__main__":
    
    while True:
        print('\nO que você deseja fazer? \n1 - Realizar Cadastro \n2 - Realizar Login \n3 - Sair')
        opcao = input()
        if opcao == '1':
            cliente.cadastrar_cliente()
        elif opcao == '2':
            cliente.realizar_login()
        elif opcao == '3':
            break
        else:
            print('Apenas são aceitos valores inteiros entre 1 e 3')
    