import hashlib
import time
import json

class Block:
    def __init__(self, data, prev_hash="", nonce=0):
        self.data = data          # Данные блока
        self.prev_hash = prev_hash  # Хеш предыдущего блока
        self.nonce = nonce        # Число для подбора хеша
        self.hash = self.calculate_hash()  # Хеш текущего блока
    
    def calculate_hash(self):
        # Создаем строку из данных блока и вычисляем хеш SHA-256
        block_string = json.dumps({
            "data": self.data,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def __str__(self):
        return f"Block(data={self.data}, prev_hash={self.prev_hash[:10]}..., nonce={self.nonce}, hash={self.hash[:10]}...)"

class Blockchain:
    def __init__(self, difficulty=5):
        self.chain = []          
        self.difficulty = difficulty  
        self.create_genesis_block()  
    
    def create_genesis_block(self):
        # Создаем начальный (генезис) блок
        genesis_block = Block(data="Genesis Block", prev_hash="")
        self.mine_block(genesis_block) 
        self.chain.append(genesis_block) 
    
    def mine_block(self, block):
        # Майним блок, подбирая nonce, пока хеш не будет иметь нужное количество нулей
        target = '0' * self.difficulty
        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = block.calculate_hash()
    
    def add_block(self, data):
        # Добавляем новый блок с данными
        prev_block = self.chain[-1]
        new_block = Block(data=data, prev_hash=prev_block.hash)
        
        print(f"Майним блок для значения: {data}")
        start_time = time.time()
        self.mine_block(new_block)  
        end_time = time.time()
        print(f"Блок успешно добыт за {end_time - start_time:.2f} секунд")
        
        self.chain.append(new_block) 
    
    def is_chain_valid(self):
        # Проверяем валидность всей цепочки
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i-1]
            
            # Проверяем целостность хеша
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Проверяем связь между блоками
            if current_block.prev_hash != prev_block.hash:
                return False
            
            # Проверяем Proof-of-Work
            if current_block.hash[:self.difficulty] != '0' * self.difficulty:
                return False
        return True
    
    def print_chain(self):
        for i, block in enumerate(self.chain):
            print(f"\nБлок #{i}:")
            print(f"Данные: {block.data}")
            print(f"Хеш предыдущего блока: {block.prev_hash}")
            print(f"Nonce: {block.nonce}")
            print(f"Хеш: {block.hash}")

def main():
    values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]
    
    # Создаем блокчейн, выбираем сложность (количество ведущих нулей в хеше)
    print("Создаем блокчейн...")
    blockchain = Blockchain(difficulty=6)
    
    # Разбиваем значения по блокам
    for value in values:
        blockchain.add_block(value)
    
    print("\nИнформация о блокчейне:")
    blockchain.print_chain()
    
    print("\nБлокчейн валиден:", blockchain.is_chain_valid())

if __name__ == "__main__":
    main()