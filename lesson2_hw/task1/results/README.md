Итоги тестирования трех последовательностей

1. Последовательность, сгенерированная с помощью библиотеки random:
- WEAK - 2
- FAILED - 1

2. Последовательность, сгенерированная с помощью библиотеки secret:
- WEAK - 3
- FAILED - 0

3. Последовательность, сгенерированная с помощью OpenSSL:
- WEAK - 3
- FAILED - 2


С помощью статистических тестов можно определить в целом слабость генератора, но они не проверяют криптографическую стойкость (непредсказуемость) генератора. 
В нашем случае библиотека secret ожидаемо дала лучшие результаты в сравнении с random, но вот с OpenSSL явно что то пошло не так, эта последовательность показала худший результат. 